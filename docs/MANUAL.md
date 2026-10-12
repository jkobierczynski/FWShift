# FWShift user manual

FWShift converts firewall policies between Palo Alto PAN-OS, Fortinet FortiOS,
Check Point, Cisco ASA, Cisco Secure Firewall (managed by a Management Center
or by its Device Manager), Sophos Firewall, pfSense, SonicWall, WatchGuard, Barracuda CloudGen Firewall, Juniper SRX and Linux iptables, and tells you,
rule by rule, how faithful the result is. It can also audit a policy: rules that allow too much,
rules that never match, loose ends; and show what each zone may reach in each
other zone. This manual covers version 0.16.

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
14. [The zone matrix](#14-the-zone-matrix)
15. [Rule usage from logs](#15-rule-usage-from-logs)

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
  `RULE_WITHOUT_EFFECT`. Rules a pfSense does not load itself are named in
  one note, `RULE_NOT_LOADED`.)
* A rule whose match cannot be expressed on the target is written
  **disabled** and listed in the report as *needs review*.
* An object that cannot be converted becomes a placeholder that matches
  nothing, with `FWSHIFT PLACEHOLDER` in its comment, so the output loads and
  the gap is visible.
* Nothing missing or unknown is read as "any".

FWShift converts the **policy**. It does not convert interfaces, routing, VPN,
users, security profiles, or system settings, and it is not a substitute for
testing the result.

> **Status.** Version 0.16 is tested against synthetic configurations. iptables
> output and input are checked against a Linux kernel (filter rules, one
> kernel and iptables version). Output for PAN-OS, FortiOS, Check Point,
> Cisco ASA, Cisco Secure Firewall, Sophos Firewall, pfSense, SonicWall, WatchGuard, Barracuda and Juniper SRX has
> not been loaded on a device or management server yet; the Check Point input format follows the
> API documentation, the ASA and FTD syntax Cisco's command references, the
> Sophos format the documentation of its XML API and the templates of
> Sophos's own SDK, and the JSON of a Management Center and of a Device
> Manager their API documentation and the tooling Cisco publishes for them.
> What pfSense makes of its configuration is taken from its source code; the
> SonicWall settings export and the WatchGuard configuration file from the
> published readers of those formats, and the REST API of a Barracuda CloudGen
> Firewall from the examples in its documentation; Junos from Juniper's
> documentation and from the grammar of a published reader of it.
> Use FWShift to produce a draft for a lab.

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

A release also carries FWShift as one file, `fwshift-X.Y.Z.pyz`. It needs
Python and nothing else, and can be copied to a machine that has no pip and
no network:

```sh
python3 fwshift-0.9.0.pyz --version
python3 fwshift-0.9.0.pyz convert running-config.xml --to fortios -o fortigate.conf
```

Wherever this manual writes `fwshift`, `python3 fwshift-X.Y.Z.pyz` does the
same, with the same exit status.

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

**Hit counters of PAN-OS and FortiOS** are not in the configuration. They are
an answer of the firewall's API, given to the audit with `--hits FILE`
(section 13):

```sh
# PAN-OS (8.1 and later), on the firewall itself; one answer per virtual system
curl -sk -H "X-PAN-KEY: $KEY" "https://fw.example.net/api/?type=op&cmd=<show><rule-hit-count><vsys><vsys-name><entry%20name='vsys1'><rule-base><entry%20name='security'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>" > hits-fw1.xml
# FortiOS: the counters of the firewall policies of a VDOM
curl -sk -H "Authorization: Bearer $TOKEN" "https://fg.example.net/api/v2/monitor/firewall/policy?vdom=root" > hits-fg.json
```

Panorama counts rules per device group and only says whether they were used;
give the answers of the firewalls themselves instead, one `--hits` per
firewall.

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

**Cisco Secure Firewall (Firepower Threat Defense): which input.** The policy
of an FTD device lives in its manager, and FWShift reads it from there: from
a Management Center (`--from fmc`) or from the Device Manager of the device
(`--from fdm`), both described below. That is the policy as it was written:
rules in their sections, objects by name, the conditions a rule has.

The `show running-config` of the device is a third way, read as an ASA
configuration. It shows what the manager deployed, in ASA syntax, and it is
the policy as far as addresses, ports and interfaces go, and no further: a
rule with application, URL or user conditions is in it **without** those
conditions. FWShift recognises such rules by the remark the manager writes
(`L7 RULE`) and converts them disabled; intrusion and file policies are not in
the device configuration at all (`FTD_CONFIGURATION`). NAT is read in full.
Use it when the manager cannot be reached.

**Cisco Secure Firewall Management Center (FMC).** There is no file to
export that FWShift reads (the `.sfo` of *Import/Export* is a binary
archive). FWShift reads what the REST API answers, as JSON: save the answers
to one file, one after the other. Any tool that calls the API will do; with
`curl` and a user that may read the configuration (Cisco's API guide says
that a user who is logged in to the web interface at the same time is logged
out there by an API login):

> None of this was run against a Management Center. The calls follow Cisco's
> REST API documentation; what the answers look like is taken from that
> documentation and from the tooling Cisco publishes. Where an answer is not
> shaped as FWShift expects, it says what it could not read rather than
> guess, but look at `fwshift inspect` before you trust a conversion.

```sh
fmc=https://fmc.example.net
curl -s -u api-user -X POST -D headers.txt -o /dev/null $fmc/api/fmc_platform/v1/auth/generatetoken
token=$(grep -i '^x-auth-access-token:' headers.txt | tr -d '\r' | cut -d' ' -f2)
domain=$(grep -i '^domain_uuid:' headers.txt | tr -d '\r' | cut -d' ' -f2)
get() { curl -sS --fail-with-body -H "X-auth-access-token: $token" "$fmc/api/fmc_config/v1/domain/$domain/$1" || echo "FAILED: $1" >&2; echo; }

# The ids of the policies and of the device: pick yours from these lists.
get "policy/accesspolicies?limit=1000"   | jq -r '.items[] | "\(.id)  \(.name)"'
get "policy/ftdnatpolicies?limit=1000"   | jq -r '.items[] | "\(.id)  \(.name)"'
get "devices/devicerecords?limit=1000"   | jq -r '.items[] | "\(.id)  \(.name)"'
acp=...; nat=...; device=...
pre=$(get "policy/accesspolicies/$acp" | jq -r '.prefilterPolicySetting.id')

{
  for kind in hosts networks ranges fqdns networkgroups protocolportobjects icmpv4objects icmpv6objects \
              portobjectgroups securityzones interfacegroups; do
      get "object/$kind?expanded=true&limit=1000"
  done
  get "policy/accesspolicies/$acp"
  get "policy/accesspolicies/$acp/inheritancesettings?expanded=true"
  get "policy/accesspolicies/$acp/accessrules?expanded=true&limit=1000"
  get "policy/prefilterpolicies/$pre"
  get "policy/prefilterpolicies/$pre/prefilterrules?expanded=true&limit=1000"
  get "policy/ftdnatpolicies/$nat"
  get "policy/ftdnatpolicies/$nat/manualnatrules?expanded=true&limit=1000"
  get "policy/ftdnatpolicies/$nat/autonatrules?expanded=true&limit=1000"
  for kind in physicalinterfaces subinterfaces etherchannelinterfaces; do
      get "devices/devicerecords/$device/$kind?expanded=true&limit=1000"
  done
} > fmc-export.json
```

(`curl` asks for the password. With a certificate that your machine does not
trust, give `curl` the certificate of its authority with `--cacert`; `-k`
switches the check off and belongs in a lab. A token is good for 30 minutes
according to the API guide; `--fail-with-body` needs curl 7.76 or newer.)

**Check that every call answered.** A call that fails (a token that ran out,
an id that is wrong) answers with an error, and `curl` saves that like any
other answer. FWShift reports an error it finds in the input, and a policy
without a list of its rules (`EXPORT_INCOMPLETE`), but it cannot miss an
answer it does not know was asked for: an object list that is missing only
shows as objects that are "not in the input in full".

Six things decide whether the export is complete:

* **`expanded=true`.** Without it a list holds names and ids only. Rules that
  are in the input by name alone are kept in their place and not converted
  (`RULES_NOT_EXPANDED`); an object that is there by name alone cannot be
  converted, and the rules that use it are written disabled.
* **Pages.** One call returns at most 1000 items. Each answer says how many
  there are (`paging.count`); with more, repeat the call with `&offset=1000`,
  `&offset=2000` and so on, and include every page. FWShift compares the
  number of rules it read with that count and reports a shortfall
  (`EXPORT_INCOMPLETE`): the rules of a missing page are simply not there,
  including its blocks.
* **The policy itself**, not only its rules: it holds the default action, the
  prefilter policy that is used and whether the policy inherits from another.
  Without it the default action is taken to block, and that is said
  (`DEFAULT_ACTION_UNKNOWN`).
* **Whether the policy inherits from another.** The mandatory rules of a
  parent policy come before the rules of yours and its default rules after
  them. The inheritance settings (the call above) say whether there is a
  parent, and which. Without them, and without anything else in the input
  that tells, FWShift converts the policy as it stands and says that a parent,
  if there is one, is missing from the result (`INHERITANCE_UNKNOWN`): a
  blocking rule of the parent would be among what is missing.
* **The policy it inherits from.** Fetch that policy, its inheritance
  settings and its rules the same way, into the same file
  (`PARENT_POLICY_MISSING` when they are not there). FWShift then reads the
  policy nothing inherits from; `--policy` names another.
* **The prefilter policy.** Its rules are evaluated before the access rules:
  a Fastpath rule lets traffic through that no access rule sees, a Block rule
  stops it. The default prefilter policy has no rules; one of your own has to
  be in the input (`PREFILTER_MISSING`).

The security zones and the interfaces of the device tell FWShift which
interface a zone holds, which a NAT rule "to the address of the interface"
needs; the interface groups are needed where a NAT or prefilter rule names
one. Objects no rule uses can be left out, and so can whole kinds of object
the policy does not use.

An input with several access control policies or NAT policies is read with
`--policy NAME` and `--nat-policy NAME` (the name, or the id where two
domains have a policy of one name). One domain is read per run.

What is in a Management Center and not in this input: intrusion, file,
SSL, identity and DNS policies, platform settings, routing and VPN. Objects
that allow **overrides** have the value of the Management Center, not that of
a device (`OBJECT_OVERRIDES`).

**Cisco Secure Firewall Device Manager (FDM).** FWShift reads the
configuration export of the device: a zip that holds one text file, a JSON
list of every object. Give FWShift the zip as it is, or the text file:

```sh
fwshift inspect export.zip
fwshift convert export.zip --to panos -o panos.set --report report.txt
```

The export is made in the web interface (in the device settings, under the
configuration export or download; the name of the page differs between
versions) or through the REST API, version 6.5 and later:

```sh
ftd=https://ftd.example.net
token=$(curl -s -X POST -H 'Content-Type: application/json' $ftd/api/fdm/latest/fdm/token \
        -d '{"grant_type": "password", "username": "admin", "password": "..."}' | jq -r .access_token)
call() { curl -s -H "Authorization: Bearer $token" "$@"; }

call -X POST $ftd/api/fdm/latest/action/configexport -H 'Content-Type: application/json' \
     -d '{"type": "scheduleconfigexport", "configExportType": "FULL_EXPORT", "doNotEncrypt": true}'
call $ftd/api/fdm/latest/jobs/configexportstatus | jq -r '.items[0] | "\(.status)  \(.diskFileName)"'
call $ftd/api/fdm/latest/action/downloadconfigfile/NAME-OF-THE-FILE -o export.zip
```

Export without encryption (`doNotEncrypt`): an encrypted zip cannot be read,
and FWShift says so. A full export is best. A partial export holds the
objects that were asked for and names the others: what is named and not in
the file cannot be converted, except the two objects every device has for
"every address", `any-ipv4` and `any-ipv6` (`PREDEFINED_OBJECT`).

What the REST API answers to `GET` requests (`/object/networks`,
`/policy/accesspolicies/default/accessrules`, `/policy/manualnatpolicies/...`
and so on), saved to a file one after the other, is read the same way. An
export says the order of the rules; a list of the API is taken in its order.

A device has one access control policy and no prefilter policy. Intrusion,
file, SSL decryption and identity policies are not converted.

FWShift wants the **security zones and the interfaces** in the input, which a
full export holds. A NAT rule of a Device Manager names interfaces, and the
zones say which zone an interface is in; where the input does not say, the
rule is read for any zone and reported (`NAT_INTERFACE`).

> None of this was run against a Device Manager either: the export format is
> taken from the import and export chapter of Cisco's API guide and from the
> API specification that ships with Cisco's Ansible modules.

**Sophos Firewall (SFOS 18 and later).** In the web admin console, go to
*Backup & firmware > Import export* and export the configuration: all of it,
or selected parts. FWShift needs the firewall rules and the NAT rules, the
hosts and services they name (IP hosts, IP host groups, FQDN hosts, FQDN host
groups, services, service groups) and, to tell which zone the interfaces of a
NAT rule are in, the zones and the interfaces. The export is a `.tar` archive
that holds one file, `Entities.xml`. Give FWShift the archive as it is, or the
XML file out of it:

```sh
fwshift inspect export.tar
fwshift convert export.tar --to panos -o panos.set --report report.txt
```

The answer of the XML API to a `Get` request holds the same entities and is
read the same way.

This export is not the **backup** of *Backup & firmware > Backup & restore*,
which FWShift cannot read. Sophos UTM (the SG series) is another product with
another configuration, and is not read either. A firewall with SFOS 17 or
older kept NAT inside its firewall rules: its rules are read, that NAT is not
(`RULE_NAT`, `RULE_TYPE_NOT_READ`).

Web server protection rules are not forwarding rules and are left out
(`WAF_RULE`). Of the system hosts a firewall creates for its own ports and
tunnels (`#Port1`, `##ALL_IPSEC_RW`), only those a rule names are kept.

**pfSense (2.6 and later, CE and Plus).** Under *Diagnostics > Backup &
Restore*, download the configuration with *Backup area* set to **All** and
without encryption. The file is `config-<host>-<date>.xml`. A backup of one
area (only the firewall rules, say) is not enough: the rules name interfaces,
aliases and virtual IPs, which are elsewhere in the file. The same file is on
the firewall as `/cf/conf/config.xml`.

```sh
fwshift inspect config.xml
fwshift convert config.xml --to fortios -o fortigate.conf --report report.txt
```

An interface that gets its address by DHCP, PPPoE, SLAAC or from another
interface (*Track interface*) has no address in the file. Rules that name it
(`WAN address`, `WAN net`, *This Firewall*) cannot be converted without it and
are written disabled, saying so. Give the address with the prefix length of
the network, for each IP version, as *Status > Interfaces* shows it:

```sh
fwshift convert config.xml --to panos -o panos.set \
    --interface-address wan=198.51.100.7/24 --interface-address wan=2001:db8:0:1::7/64
```

The interface is named by its name in the file (`wan`, `opt2`) or by its
description (`WAN`). The zones of the policy are the interfaces, by their
descriptions; an interface group is not a zone, a rule of a group is a rule of
each of its interfaces.

The order in which pfSense evaluates the rules of interface groups changed
after 2.7.2 (the version in the file, `<version>`, above 23.3): FWShift orders
them as the version in the file says, and reports it where two groups share
an interface and the order is not the same both ways (`RULE_ORDER_VERSION`).
Rules pfSense itself would not load (an alias that is not there, an interface
that is not enabled) are not converted and named in one note
(`RULE_NOT_LOADED`). The rules of packages (pfBlockerNG and the like), of the
captive portal and of IPsec, OpenVPN and other services that pfSense makes
itself are not in the file as rules, and are not converted
(`PFSENSE_AUTOMATIC_RULES`).

The configuration of an **OPNsense** firewall looks alike, but keeps its
aliases, automatic rules and parts of its NAT elsewhere: FWShift refuses it
with that reason rather than read it as a pfSense.

**SonicWall (SonicOS 6.5 and 7).** Export the settings: on SonicOS 7 under
*Device > Settings > Firmware and Settings*, *Import/Export Configuration >
Export Configuration*; on SonicOS 6.5 under *Manage > Updates > Firmware &
Settings*, *Export Settings* (the names of the menus differ a little between
releases). The file ends in `.exp`. FWShift reads it as
it is, and also the decoded text (`base64 -d settings.exp | tr '&' '\n'`):

```sh
fwshift inspect sonicwall.exp
fwshift convert sonicwall.exp --to panos -o panos.set --report report.txt
```

SonicWall does not document this file beyond its encoding. FWShift reads the
keys that every published reader of the format agrees on (address and
service objects and groups, zones, interfaces, access rules, NAT policies)
and says so in the report (`SONICWALL_FORMAT`). Objects SonicOS has by itself
and that an export does not list (`X1 IP`, `X0 Subnet`, `LAN Subnets`,
`Firewalled Subnets`, `HTTPS`) are worked out from the interfaces of the
export, or taken from the defaults of SonicOS, and named (`DEFAULT_OBJECT`).
An interface that gets its address by DHCP or PPPoE has none in the file:
give it with `--interface-address X1=198.51.100.7/24`.

Firewalls in Policy mode (SonicOS 7 *SonicOSX*, NSsp) keep security
policies of another kind, which are not read.

**WatchGuard (Fireware 12).** Open the configuration in Policy Manager and
save it with *File > Save > As File*: an XML file whose root is `<profile>`.
The Web UI downloads the same file, zipped (*System > Configuration File*):
unzip it first.

```sh
fwshift inspect firebox.xml
fwshift convert firebox.xml --to panos -o panos.set --report report.txt
```

WatchGuard does not document this file. FWShift reads the elements the
published readers of the format agree on (interfaces, address groups,
aliases, services, policies and the static NAT actions they use) and says so
in the report (`WATCHGUARD_FORMAT`). In automatic policy order the Firebox
orders the policies itself; FWShift reads them in the order of the file and
says so (`POLICY_ORDER_AUTOMATIC`): switch Policy Manager to manual order
before you save the file, and the order of the file is the order of the
Firebox.

**Barracuda CloudGen Firewall (8.0 and later).** The firewall has no export of
its rules that another program can read: its configuration backup (a PAR
file) is in a format Barracuda does not document. FWShift reads what the REST
API of the firewall answers, saved one answer after the other in one file.
Switch the API on (*Configuration Tree > Box > Infrastructure Services > REST
API Service*, HTTPS) and create an access token for an administrator who may
read the configuration. Then fetch the forwarding rules and every network and
service object they name:

```sh
FW=https://fw.example.net:8443
H="X-API-Token: <token>"
curl -sS -H "$H" "$FW/rest/config/v1/forwarding-firewall/rules?expand=true&envelope=false" > barracuda.json
curl -sS -H "$H" "$FW/rest/config/v1/forwarding-firewall/objects/networks/Office-LAN" >> barracuda.json
curl -sS -H "$H" "$FW/rest/config/v1/forwarding-firewall/objects/services/HTTP%2BS" >> barracuda.json
fwshift inspect barracuda.json
```

`GET .../objects/networks` and `.../objects/services` list the names of the
objects; fetch each one the rules name. What is still missing, `fwshift
inspect` lists (`OBJECTS_MISSING`): the rules that name it are not used until
it is there. Only the name `Any` is the object Any. Barracuda documents the
API by examples only; the keys FWShift reads are those (`BARRACUDA_FORMAT`).
The rules of a rule list a rule cascades to, NAT (the actions Dst NAT and
Map, connection objects) and the host firewall are not read.

**Juniper SRX (Junos OS).** Export the configuration as set commands, with
what groups give written where it applies:

```
show configuration | display inheritance no-comments | display set | no-more
```

Plain `show configuration | display set` and the configuration in braces
(`show configuration`, or a saved `juniper.conf`) are read as well. A
configuration that takes parts of its security policy or applications from
groups (`apply-groups`) without them shown where they apply is refused with
that reason: export it with `display inheritance`.

```sh
fwshift inspect srx.conf
fwshift convert srx.conf --to panos -o panos.set --report report.txt
```

Only the root system is read; logical systems and tenants are named
(`PARTS_NOT_READ`). Predefined applications (`junos-http`, ...) are not in a
configuration: FWShift takes those it knows from a table of its own and says
which (`PREDEFINED_APPLICATIONS`); one it does not know, or knows two
definitions of (`junos-ping`), makes the policy unusable.

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

Only these answers are read. JSON in another layout, such as a hand-written or
generated "policy" with `access-layers`, `sections` and `rules` that name their
objects, holds no `rulebase` and is refused with `no rulebase found`, which
lists the keys it does hold. The same goes for an input of object listings
alone (`show objects`, `show access-layers`): there is no rule to convert.

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

Two more things are worth adding:

* **Hit counts.** Add `show-hits true` to the `show access-rulebase` calls
  (optionally `hits-settings.from-date 2026-07-01 hits-settings.to-date
  2026-09-30`, and `hits-settings.target <gateway>` for one gateway). Each
  rule then carries its hit count, which the audit reads (`UNUSED_RULE`,
  section 13). Nothing else changes.
* **Access roles.** A rule cell names an access role by reference; what the
  role holds (networks, users, machines) is only in the export when the role
  objects are:
  `mgmt_cli show access-roles details-level full limit 500 --format json -s sid.txt > roles.json`,
  added to the array with the other answers. Without it the roles are
  unsupported objects and their rules are written disabled.

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
fwshift convert INPUT --to FORMAT [options]
```

`FORMAT` is one of `panos`, `fortios`, `checkpoint`, `asa`, `fmc`, `fdm`,
`sophos`, `pfsense`, `sonicwall`, `watchguard`, `barracuda`, `junos`,
`iptables`, `ip6tables` and `json` (the neutral model; see `--to json` below).

`INPUT` is a file, or `-` for standard input.

**Source**

| Option | Meaning |
|---|---|
| `--from FORMAT` | Source format: one of the formats above, except `json`. Detected when left out: a tar archive, or XML that starts with `<Configuration>` (or with the `<Response>` of the Sophos XML API), is Sophos Firewall; XML that starts with `<pfsense>` is pfSense; XML that starts with `<profile>` is WatchGuard; Base64 that decodes to the keys of a settings export, or those keys themselves, is SonicWall; other XML is PAN-OS; JSON with the keys of the REST API of a CloudGen Firewall (`references`, `deactivated` and `ipVersion` in rules, or `included` entries of network objects) is Barracuda; other JSON is a Management Center (`fmc`) or a Device Manager (`fdm`) when it holds objects of the types one of them writes, and Check Point otherwise; a zip that holds the export of a Device Manager is `fdm`; a file that starts with a table (`*filter`) or the header of `iptables-save` is iptables, a file with lines `set security ...`, `set system ...` and the like at the start of a line, or the top of a configuration in braces (`version ...;`, `security {`), is Juniper SRX; a file with an `ASA Version` line or with `access-list ... extended`, `object network` and similar lines is Cisco ASA, anything else FortiOS. |
| `--vsys NAME` | PAN-OS source with several virtual systems: the one to read. |
| `--device-group NAME` | Panorama source: the device group to read, with its parents and `shared`. |
| `--vdom NAME` | FortiOS source with several VDOMs: the one to read. |
| `--layer NAME` | Check Point source with several access layers: the one to read. |
| `--policy NAME` | Management Center source with several access control policies: the one to read, by its name or its id. Without it the policy that no other policy in the input inherits from is read, if there is one such policy. |
| `--nat-policy NAME` | Management Center source with several NAT policies: the one to read, by its name or its id. |
| `--interface-address INTERFACE=ADDRESS/BITS` | pfSense and SonicWall sources: the address of an interface that gets it by DHCP, PPPoE, SLAAC or from a tracked interface, which is then not in the file (SonicWall: IPv4, by the name of the interface, `X1`). `INTERFACE` is the name of the interface (`wan`, `opt1`) or its description (`WAN`), `BITS` the prefix length of its network. One address per IP version and interface; repeatable. Without it, rules that name such an address or network are written disabled (section 3). |

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
| `--to fmc` | A Python script that creates the policy on a Cisco Secure Firewall Management Center through its REST API: objects, a new access control policy, a new NAT policy (section 10). |
| `--to fdm` | A file for the configuration import of a Cisco Secure Firewall Device Manager: objects, access rules, manual NAT rules (section 10). |
| `--to sophos` | An `Entities.xml` for *Import export* of a Sophos Firewall (SFOS 18 and later). With `-o NAME.tar`, the archive an import takes. |
| `--to sonicwall` | Commands of the SonicOS 7 command line, to paste into an SSH session: objects, NAT policies, access rules (section 10). |
| `--to junos` | `set` commands for an SRX, for `load set`: applications, the global address book, security policies, NAT (section 10). |
| `--to barracuda` | A shell script that creates network objects, service objects and forwarding rules on a Barracuda CloudGen Firewall through its REST API, with curl (section 10). |
| `--to watchguard` | The policy part of a Policy Manager configuration file (Fireware 12): address groups, aliases, services, static NAT actions and policies in manual order, to merge into a configuration of the target (section 10). |
| `--to pfsense` | A configuration file with the areas Aliases, NAT and Firewall Rules, for *Diagnostics > Backup & Restore* of pfSense 2.7 or later. Each restore of an area **replaces** that area (section 10). |
| `--to iptables` | A file for `iptables-restore`: the IPv4 half of the policy. |
| `--to ip6tables` | A file for `ip6tables-restore`: the IPv6 half. |
| `--to json` | The neutral model as JSON, for inspection or other tools. It is the model as it was read: the audit options cannot be combined with it. Each rule carries what the source calls it (`source_ids`: the uid of a Check Point rule, the name and uuid of a PAN-OS rule, the policy ID and uuid of a FortiOS policy), the devices it is installed on where the source limits that (`targets`), and its hit count where the input has one (`hits`). |
| `--target-vsys NAME` | PAN-OS: prefix commands with `vsys NAME`. Default: a single-vsys firewall, no prefix. |
| `--target-device-group NAME` | Panorama: write into this device group; rules go to its pre-rulebase. |
| `--target-shared` | Panorama: write into `shared`; rules go to the shared pre-rulebase. |
| `--target-nat-zone ZONE` | PAN-OS: destination zone for NAT rules of a source that names none (Check Point, some iptables and ASA rules). Without it those NAT rules are skipped. ASA: the interface for source NAT "to the address of the outgoing interface" where the rule does not name one. Management Center and Device Manager: the zone of that interface. pfSense: the interface a port forward of a rule for every zone is written for, and the interface outbound NAT is written for where a rule does not say where its traffic leaves. |
| `--target-vdom NAME` | FortiOS: wrap the output in `config vdom` / `edit NAME`. |
| `--policy-id-start N` | FortiOS: number policies from N. Default is `edit 0`, which lets the FortiGate pick free ids and appends after existing policies. |
| `--target-layer NAME` | Check Point: the access layer the rules are written to. Default `Network`. It must exist. |
| `--target-package NAME` | Check Point: the policy package whose NAT rulebase gets the NAT rules. Default `Standard`. |
| `--target-gateway NAME` | Check Point: the gateway or cluster object to hide behind, for source NAT "to the address of the outgoing interface". Without it such rules are skipped unless the source gives an address. |
| `--target-prefix TEXT` | Check Point, ASA, Sophos, pfSense, SonicWall, WatchGuard, Barracuda, Juniper, Management Center and Device Manager: put `TEXT` in front of the name of every object (on an ASA also every access list) that is created, so that none collides with one the target has. On a Sophos Firewall and on a Device Manager an import overwrites an object of the same name; the script for a Management Center stops before it creates anything when a name is taken. Up to 20 letters, digits, periods, underscores and hyphens for the two Cisco managers. |
| `--target-policy NAME` | Management Center: the name of the access control policy and of the NAT policy the script creates. Default `FWShift`. The script can be given another name when it is run (`--name`). |

**Adapting the policy**

| Option | Meaning |
|---|---|
| `--zone-map SRC=DST` | Use `DST` wherever the source names zone or interface `SRC`. Repeatable. For iptables and ASA this is how a zone becomes an interface name, and the other way round; for pfSense how it becomes an interface (`lan`, `opt1`) or an interface group. |
| `--zone-network ZONE=NET[,NET...]` | ASA, pfSense and Barracuda targets: the networks that lie behind a zone (SonicWall: the zone an address object is created in; Barracuda: both sides of a rule, which names no zone) (its name after `--zone-map`). Repeatable. An ASA access list, like a rule of pfSense, cannot name the interface traffic leaves by; with the networks FWShift keeps a rule for one destination zone to that zone (section 8). Networks may be addresses, prefixes or ranges. Give the networks of **every** zone, IPv4 and IPv6: nothing is assumed about a zone without networks, or about an address that lies in none of them. Of two networks, one inside the other, the smaller one decides, as a route would: give the zone that has the default route `0.0.0.0/0,::/0`, which then says "everything that is not behind another zone". |
| `--interface-map SRC=DST` | Map a source interface to a target interface: zone members written for FortiOS, source NAT to an interface address on PAN-OS, and the interfaces of a NAT rule on Sophos Firewall, SonicWall and a Device Manager, which match interfaces and not zones (SonicWall: `X1`, `X3:V10`); for a Barracuda target, the interface of the entries of the source of a rule in that zone (`port2`). For those two, map every interface of a zone the NAT rules name (for an iptables or ASA source, whose zones are interfaces, that is the zone name itself); for a Device Manager `DST` is the logical name of the interface (`inside`, `outside`). Repeatable. |
| `--app-map FILE` | JSON file that adds or overrides application port definitions (section 9). |
| `--prune-unused` | Leave out objects that no rule or NAT rule uses, directly or through a group. |

**Output**

| Option | Meaning |
|---|---|
| `-o FILE`, `--output FILE` | Where the configuration goes. Default: standard output. With `--to sophos`, a name that ends in `.tar` gives the archive an import takes, with the XML inside. |
| `--report FILE` | Where the text report goes. Default: standard error. |
| `--report-json FILE` | Also write the report as JSON. |
| `--strict` | Exit with status 2 when anything needs review. |
| `-q`, `--quiet` | Do not print the report or the one-line summary. |
| `--audit` | Audit the policy before and after the conversion, and carry out the actions set for the checks (section 13). The audit options below switch it on as well. |
| `--audit-config FILE` | JSON file with the actions, accepted rules, thresholds and service lists of the audit. |
| `--audit-action CHECK=ACTION` | What to do with the findings of a check: `off`, `accept`, `report`, `disable`, and for shadowed rules `reorder`. Not every check takes every action (section 13). Repeatable. |
| `--audit-accept RULE[=CHECK,...]` | Let a rule (or a NAT rule, or an object) pass a check, or every check. `*` and `?` stand for any text and any one character. Repeatable. |
| `--audit-fail-on LEVEL` | Exit with status 3 when a finding of this level (`info`, `low`, `medium`, `high`) or higher is reported. |
| `--hits FILE` | Hit counters of the firewall, for `UNUSED_RULE` and `NO_USAGE_EVIDENCE` (section 13): the XML answer of PAN-OS `show rule-hit-count`, or the JSON answer of the FortiOS monitor `firewall/policy` (section 3). Repeatable: the counters of several firewalls are added up. A Check Point rulebase exported with `show-hits` carries its own. |
| `--hits-since YYYY-MM-DD` | The hit counters have counted since this day (UTC), where they do not say so themselves (Check Point without a rule that was ever hit, FortiOS). Your word: it decides whether a zero is `UNUSED_RULE` (section 13). |

All output is UTF-8.

### `fwshift audit`

```
fwshift audit INPUT [--from ...] [-o FILE] [--json] [--audit-config FILE]
                    [--audit-action CHECK=ACTION] [--audit-accept RULE[=CHECK,...]] [--audit-fail-on LEVEL]
                    [--hits FILE] [--hits-since YYYY-MM-DD]
fwshift audit --list-checks
```

Audits a configuration of any format that can be read and prints what it
found (section 13). It takes the source options of `fwshift convert`
(`--vsys`, `--interface-address` and the others). Nothing is converted and nothing is changed: an action
such as `disable` is shown as what a conversion would do. `--json` writes the
findings as JSON; `--list-checks` shows the checks, their levels and the
actions each can take.

### `fwshift matrix`

```
fwshift matrix INPUT [--from ...] [--vsys ...] [--device-group ...] [--vdom ...] [--layer ...]
                     [--policy ...] [--nat-policy ...] [--interface-address ...] [-o FILE] [--json | --csv] [--summary]
                     [--network-zone NAME[@ZONE]=NETWORK[,NETWORK...]] [--audit-config FILE]
```

Shows what each zone may reach in each other zone, on which services and
through which rules (section 14). Nothing is converted.

| Option | Meaning |
|---|---|
| `-o FILE` | Where the matrix goes. Default, and `-`: standard output. |
| `--json`, `--csv` | The matrix as JSON, or as CSV with a line per rule and conduit. |
| `--summary` | Text output: the grid and what each conduit allows, without the rules. |
| `--network-zone NAME[@ZONE]=NETWORK[,NETWORK...]` | A zone of your own, given as networks. Repeatable. The matrix is then between these zones. `@ZONE` names the zone (or zones, separated by commas) of the policy the networks lie behind. |
| `--audit-config FILE` | The configuration file of the audit: its lists of risky and industrial services and applications are used. |

### `fwshift inspect`

```
fwshift inspect INPUT [--from ...] [--vsys ...] [--device-group ...] [--vdom ...] [--layer ...]
                      [--policy ...] [--nat-policy ...] [--interface-address ...]
```

Prints what was read and the findings raised while reading. Nothing is
converted.

### `fwshift usage`

```
fwshift usage INPUT [--from ...] [--layer ...] [--logs FILE ...] [--store FILE] [--since DAYS|YYYY-MM-DD]
                    [--until YYYY-MM-DD] [--gateway NAME[=LOGNAME,...] ...] [--log-year YYYY] [--log-offset +HH:MM]
                    [--roll-up N] [-o FILE] [--json] [--html FILE] [--unchanged-since YYYY-MM-DD]
                    [--audit-config FILE] [--audit-action CHECK=ACTION] [--audit-accept RULE[=CHECK,...]]
                    [--audit-fail-on LEVEL] [--hits FILE] [--hits-since YYYY-MM-DD]
```

Reads the logs of the firewall and says which rules, objects and services of
the policy they show used (section 15). A Check Point, PAN-OS, FortiOS or
iptables policy, in this version. Nothing is converted.

| Option | Meaning |
|---|---|
| `--logs FILE` | A log file. Check Point: what Log Exporter sends (its syslog, splunk or cef format), or the JSON answer of `show-logs`. PAN-OS: the traffic logs a firewall or Panorama sends to syslog in the default format, or the CSV export of the traffic logs. FortiOS: the traffic logs a FortiGate sends to syslog in its default format (also forwarded by a FortiAnalyzer). iptables: the kernel lines of its `LOG` rules, as syslog or `journalctl` writes them. Repeatable. A file whose content is in the store already is not read again. |
| `--store FILE` | Keep the connections in this file (SQLite) and add to it on every run. Without it nothing is kept. With it and without `--logs`, the report is made from what the store holds. |
| `--since DAYS\|YYYY-MM-DD` | The first day of the window: a number of days back from its last day (`30d`), or a day. Default: `usage_days` (90). |
| `--until YYYY-MM-DD` | The last day of the window. Default: the last day the store has logs of. |
| `--gateway NAME[=LOGNAME,...]` | A gateway the policy is installed on. A gateway that sent no logs proves nothing for its rules; this is how a gateway that sent none at all becomes known. `NAME=LOGNAME,...` names the members of a cluster: install-on names the cluster, its members log under their own names. Repeatable. For iptables, PAN-OS and FortiOS, the firewalls that run the policy: lines of other hosts are not counted, unless the rule they name is installed on them (Panorama). A PAN-OS firewall logs under its serial number, which is what Panorama's targets name: `--gateway pa-edge=012801000001` gives it a name. |
| `--log-year YYYY` | iptables: the year of the first line of a log whose times have none (the old syslog form, `Oct 12 10:00:00`). The year goes up where the months run back. |
| `--log-offset +HH:MM` | iptables, PAN-OS, FortiOS: the offset from UTC of times that give none (`+02:00`, `-05:00`, `Z`). PAN-OS and FortiOS write the firewall's local time; a PAN-OS line of 10.0 or later and a FortiOS line with `eventtime` or `tz` carry their zone. Without it, times without a zone are read as UTC, and the report says how many were. |
| `--unchanged-since YYYY-MM-DD` | The rules have been as they are since this day, where the export does not say when they were changed (iptables, PAN-OS and FortiOS configurations never do; for PAN-OS the answer of `show rule-hit-count`, given with `--hits`, does). Your word: without it, no rule is called unused. Also an option of `fwshift audit` and `fwshift convert`. |
| `--roll-up N` | Addresses kept per rule and side as they are (per pair of interfaces, for logs that name no rule); beyond, an address is kept as its /24 (IPv6: /64). Default 256. |
| `-o FILE`, `--json`, `--html FILE` | Where the report goes, as JSON instead of text, and also as a page of its own. |

The audit options choose what is done with the findings of the four checks
of use (the other checks are for `fwshift audit`).

`fwshift audit` and `fwshift convert` take `--usage-store FILE`: what the
store says about each rule over the last `usage_days` days it holds, for the
same checks (and `UNUSED_RULE=disable` in a conversion); `--usage-gateway`
is `--gateway` for them.

### Exit status

| Status | Meaning |
|---|---|
| 0 | Done. For a conversion: converted; the report may still hold findings. |
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
| `WAF_RULE` | R, skipped | Sophos source: a web server protection rule. The firewall answers for the web server itself (a reverse proxy), which is not a forwarding rule. Publish the server on the target in its own way. |
| `RULE_TYPE_NOT_READ` | R, skipped | Sophos source: a rule of a type FWShift does not know. SFOS before version 18 published servers with rules of a type of their own. |
| `RULE_NAT` | R | Sophos source: the rule itself translates the source address, as SFOS before version 18 wrote NAT. The rule is converted, that translation is not. |
| `RULE_MATCHES_NOTHING` | I, skipped | Sophos source: the exclusions of the rule take all of what it matches. It never applied, and is left out. |
| `EXCLUSION_ZONES` | A (R on a blocking rule) | Sophos source: "any zone except X" is written as the other zones the input defines. A zone that is not in the input, or is added to the firewall later, is not among them: a blocking rule no longer blocks its traffic. Export the zones with the rules. |
| `HANDLING_NOT_CONVERTED` | I | Sophos source: what else the rule does with the traffic it matches (traffic shaping, DSCP marking, a gateway of its own, an element FWShift does not know that is no match criterion) is not converted. |
| `EXCLUSION_AS_ADDRESSES` | I | Sophos source: an exclusion of addresses from a list of addresses is written as the addresses that are left. |
| `IP_FAMILY` | A | Sophos source: a rule of the IPv4 (or IPv6) rulebase whose addresses do not say which of the two it is: host names on both sides. In the model, and on the target, it matches both IP versions. |
| `NEGATION` | R, disabled or skipped | To Sophos: several fields of the rule are negated, and more than one of them cannot be written as the addresses that are left (a host name). Exclusions apply together, so two of them would say something else (section 8). To a Management Center or a Device Manager, whose rules cannot negate: a negated service (written disabled for a Management Center, left out for a Device Manager), or negated addresses that hold a host name: that rule is left out on both, because written without its negation it would say the opposite. |
| `NEGATION_AS_ADDRESSES` | I | To Sophos: of several negated fields one is an exclusion; the others are written as the addresses that are left, which matches the same traffic. To a Management Center or a Device Manager: every negated address list is written that way, as range objects and the predefined object for the other IP version. |
| `APP_PORTS` | R, disabled | To Sophos, a Management Center or a Device Manager: the ports of an application hold something a service of the target cannot say (SCTP ports). |
| `SCHEDULE` | R, disabled | The rule had a schedule; converted without it, it would apply at all times. |
| `SERVICE_NEGATE` | R, disabled | To PAN-OS or ASA: a negated service match does not exist there. On an ASA only a remark is written for the rule: an inactive entry without the negation would say the opposite. |
| `EGRESS_INTERFACE` | A, or R and disabled | To ASA or pfSense: the rule is for traffic to certain zones, and an access list entry cannot name the interface traffic leaves by. A: the rule names destination addresses and is written for those, by whatever interface they are reached; also on an intrazone rule, which an ASA only serves with `same-security-traffic permit intra-interface`. R, disabled: the rule is for any address; give the networks behind the zones with `--zone-network`, or the rule a destination. |
| `EGRESS_BY_NETWORKS` | I or A | To ASA or pfSense: with `--zone-network`, the networks given for the other zones were left out of the destination of the entry, which keeps the rule to its zones. A: the networks do not cover every address; what they leave out lies behind no zone that is known, so a permit rule for any address does not cover it and a deny rule does (`ZONE_NETWORK_GAP`). |
| `EGRESS_NO_ADDRESS` | A or R, skipped | To ASA or pfSense: by the networks given with `--zone-network`, no address of the destination lies behind the zones the rule is for, so it matched nothing and is left out (or, with several source zones, has no entry for some of them). R for a deny rule: if one of the networks is wrong, a deny is missing. |
| `NEGATION_EXPANDED` | I | To ASA: an access list cannot negate. The negated address list was written as the address ranges it leaves, which matches the same addresses. |
| `NEGATION_NOT_STATIC` | R, disabled | To ASA: a negated list with a host name. What it leaves cannot be written out; only a remark is written for the rule. |
| `IMPLICIT_PERMIT` | I | ASA source: a rule for an interface without access list, which the ASA lets send traffic to interfaces of a lower security level (section 8). |
| `NO_SERVICE` | R, disabled | To PAN-OS: none of the rule's services could be converted. |
| `RULE_TYPE` | R, disabled | To FortiOS, Sophos, iptables, a Management Center or a Device Manager: an intrazone or interzone rule with zone `any` cannot be written as interface or zone pairs. To ASA: an intrazone rule with zone `any`. |
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
| `NO_COMMON_FAMILY` | R, skipped (I to ASA) | Source and destination share no IP version, or a negation excludes everything: the rule matches nothing. To Sophos also: the only services of the rule are ICMP in the IPv6 rulebase, or ICMPv6 in the IPv4 one. |
| `UNKNOWN_ATTRIBUTES` | R | FortiOS or Check Point source: the rule has attributes or fields FWShift does not know. If one of them narrows the match, the converted rule is wider. Check them. |
| `NAT_ADDRESS_EXPOSED` | R | The rule covers addresses on one side of a destination NAT without the addresses that go with them on the other side, and the two platforms look rules up on different sides of the translation (section 8). The message names the addresses. The rule matches traffic it did not match on the source, or the other way round for a deny. Also raised for a rule that names both sides, for the part that has no counterpart. |
| `NAT_PORT_EXPOSED` | R | The same for ports: the service of the rule covers the port on one side of a port translation and not the port on the other, so the rule applies to traffic it did not apply to on the source. Looked at for rules to any destination too. Withdrawn where the target looks rules up as the source did and gets the NAT rule. |
| `NAT_PORT_TRANSLATION` | R | A destination NAT used by this rule also changes the port, and the service of the rule names the port of one side only. FortiOS policies, ASA access lists and iptables rules name the mapped port, PAN-OS and Check Point rules the original one; correct the service by hand. Not raised for a service that holds both ports. |
| `NAT_DESTINATION_WIDENED` | R | The rule names part of what a destination NAT translates, and that NAT does not map address for address (several addresses to one, or to a pool). On the other side of the translation the part cannot be told apart: the rule now covers all of it. Or, for a target that looks rules up after destination NAT, the NAT rule translates only some of the services of the rule: for the others the rule now names the translated address, reached directly. |
| `NAT_REDIRECT` | R | iptables source: a DNAT rule without a destination address sends traffic for every destination to one address, and this rule matched it there. A platform that looks rules up before NAT cannot match that traffic with the converted rule: write the rule for the original destinations. |
| `NAT_DESTINATION_REWRITTEN` | A | The destination was changed, or extended, to the address on the other side of a destination NAT. A rule for part of a translated network gets the same part of the other side. Check that the rule is meant to cover that traffic. |
| `DENY_AND_VIP` | A | FortiOS source: a deny policy covers a virtual IP but has no `set match-vip enable`. FortiOS may have let that traffic through to a later policy; the converted rule blocks it. |
| `FQDN_FAMILY` | A | To PAN-OS or Check Point: an FQDN that FortiOS resolved for one IP version is resolved for both on the target, and this rule can match the other version. |
| `PROTOCOL_AS_APP` | A | To PAN-OS: ICMP or IP-protocol services became applications (`ping`, `icmp`, `gre`, ...). Verify the App-ID names. |
| `ICMP_TYPE` | A | To PAN-OS: a service for one ICMP type became App-ID `icmp`, which matches every type. |
| `PROFILES_NOT_CONVERTED` | A | Security profiles on the rule are not converted. Attach equivalent inspection on the target. |
| `PROFILES_BY_NAME` | I | PAN-OS to PAN-OS: profiles are referenced by name and must exist on the target. Sophos to Sophos: the same for the policies of a rule (web filter, intrusion prevention, application control and the scanning it switches on). |
| `DEVICE_TARGET` | R | Panorama or Check Point source: the rule is installed on selected devices only. Decide whether it belongs on the target. |
| `ACCESS_ROLE` | R | Check Point source: the rule matches the networks of an access role for its users. The users are names of Check Point identities (Active Directory, LDAP or internal groups, identity tags; `known-user` for "all identified users") and are kept as the rule's users: PAN-OS writes them as `source-user`, which must name users or groups the firewall knows; the other targets write the rule disabled (`USER_MATCH`). A cell with roles of different users became one rule per set of users (section 8). |
| `RULE_SPLIT` | I | One rule became several: one per zone pair on FortiOS, Sophos and the two Cisco managers, or one for port-based and one for application-based services on PAN-OS. To a Management Center or a Device Manager also: one rule per set of source ports, because source ports and destination ports are two conditions of a rule there that must both hold (section 8). Sophos source: a rule with exclusions of several kinds became one rule per kind (`name`, `name-2`, ...), which between them match what the one rule matched (section 8). |
| `RESET_ACTION` | I | A reset action has no exact equivalent: deny on FortiOS and ASA, a plain `REJECT` on iptables when the rule is not TCP only, `Reject` on Check Point and on Sophos (which answers the sender only), *Block with reset* on a Management Center (which resets both sides), *Block* on a Device Manager (which answers nobody). |
| `ATTRIBUTES_IGNORED` | I | FortiOS source: NAT details such as `fixedport` have no equivalent. ASA, Management Center or Device Manager source, on a NAT rule: options such as `dns`, round robin, extended PAT or the fallback to the interface address. |
| `MONITOR_RULE` | I, skipped | Management Center source: a rule with the action *Monitor*. It logs the traffic and leaves the decision to the rules below it: there is nothing to convert. |
| `INTERACTIVE_BLOCK` | A | Management Center source: *Interactive Block* (with or without reset) shows web users a page from which they can go on to the site. It is converted as a rule that blocks. |
| `PREFILTER_AS_TRUST` | I | Management Center source, to a Management Center or a Device Manager: a Fastpath rule of the prefilter policy is written as an access rule with the action *Trust*, in the place it had before the access rules. Both let the traffic through without inspection; a Trust rule is evaluated by the access control policy, a Fastpath rule before it. |
| `PREFILTER_ANALYZE` | I, skipped; or R | Management Center source. On a prefilter rule with the action *Analyze* (I, skipped): it hands its traffic to the access rules, which is what happens to traffic no prefilter rule matches, so there is nothing to convert. On a prefilter rule that blocks, or on the default action of the prefilter policy (R): a rule above it hands part of its traffic to the access rules, and one list of rules cannot make that exception: the rule now blocks that traffic too. A Fastpath rule in that position is not converted at all (`UNSUPPORTED_MATCH`): it would let through what the access rules were to decide. |
| `TUNNEL_RULE` | A or I | Management Center source: a tunnel rule of the prefilter policy is converted as a rule for the protocol that carries the tunnel (GRE, IP in IP, IPv6 in IP, Teredo on UDP port 3544) between the tunnel endpoints. What the source did with the connections inside the tunnel is not converted. I on the second rule that a rule for both directions becomes (`name-reverse`). |
| `DISABLED_RULE` | I, skipped | To a Device Manager: the rule is disabled on the source. A Device Manager has no rules that are switched off, so it is left out. |
| `NO_MATCH` | I, skipped | To a Management Center or a Device Manager: the rule matches nothing (a negation that leaves no address or no service). It is left out. |
| `RULE_HALF_NOT_LOADED` | I | pfSense source: a rule for IPv4 and IPv6 of which pfSense loads only one half, because an interface it names has no network or address of the other version. Only that half is converted, as pfSense has it. |
| `NEGATED_LIST` | R | pfSense source (2.6, and IPv6 of WAN and LAN on 2.7): "not" the network of an interface that has virtual addresses in other networks. pfSense writes that as a list of negated networks, which pf reads as every address: the converted rule says so too. Probably not what was meant; check the rule on the firewall. |
| `AUTOMATIC_RULE` | I or A | pfSense source: a rule that pfSense adds by itself, converted as a rule of its own: what *Block private networks and loopback addresses* of an interface drops, what a port forward with the filter rule association *Pass* passes (A: unlike the port forward, the rule also passes what is sent to the translated address directly). On a NAT rule: what automatic outbound NAT translates. |
| `POLICY_ROUTING` | I | pfSense source: the rule sends what it passes to a gateway of its own. That is routing and not converted. |
| `STATELESS_RULE` | A | pfSense source: the rule passes packets without keeping state; on pfSense the answers need a rule of their own. The model is about connections, and the converted rule lets the answers through. |
| `FLOATING_AFTER_NAT` | R | To pfSense: a rule that blocks traffic leaving by an interface became a floating rule, which pf looks at after outbound NAT, and it names a source. The file holds no NAT area, so the firewall keeps the outbound NAT it has; where that translates the source (automatic outbound NAT does, on an interface with a gateway), the rule no longer matches. Give the networks of every zone with `--zone-network`: the rule is then written for the interfaces traffic arrives on. |
| `PROTOCOL_NOT_AVAILABLE` | R, disabled | To pfSense: a rule names one protocol, from a list; an IP protocol that is not on the list cannot be written. |
| `DEFAULT_RULE_ASSUMED` | A | SonicWall source: the export holds no rule for all traffic between two zones, and SonicOS allows it by default for zones of their security types. A rule that allows it was added at the end of the pair. |
| `INCOMPLETE_ADDRESS_PAIR` | I | FortiOS source: addresses of one IP version on one side only. FortiOS cannot match that version, so they were left out. |

### NAT rules

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `NAT_NOT_CONVERTED` | R, skipped | The rule uses something that is not converted (NAT64, dynamic destination translation, an unconvertible object, an ASA NAT line that could not be read in full, a Sophos NAT rule with an element FWShift does not know or a link to a firewall rule that is not in the input), or something the target cannot say: the message names it. To Sophos: a translation to something that is not one address, one range or one host name; a port translation whose rule has no service of exactly one port; a translation address for address between a different number of addresses. To PAN-OS, a rule without a destination zone needs `--target-nat-zone`; to Check Point, source NAT to the outgoing interface needs `--target-gateway`; to ASA it needs an interface, from the rule or from `--target-nat-zone`. |
| `NAT_ORDER` | R | From PAN-OS or Check Point to FortiOS, iptables or ASA: the source applies one NAT rule to a connection, the first that matches; the target translates destinations and sources apart. This rule now also applies to traffic that another rule used to claim, or loses its source translation to one (section 8). On every target: a NAT rule above this one was not converted, and its traffic now reaches this rule. |
| `NAT_REVERSE_DIRECTION` | A | ASA, Management Center or Device Manager source: a static twice NAT rule (a manual rule with a destination) also translates connections opened from the other side. That direction is not converted. |
| `NAT_ZONE_BY_ROUTE` | I | ASA source: the destination zone of a NAT rule that translates the destination is the zone its original address is reached in, taken from the interface addresses and static routes. |
| `NAT_DYNAMIC_ONE_ADDRESS`, `NAT_STATIC_SIZE` | A | To ASA, a Management Center or a Device Manager: dynamic NAT to a single address is port address translation there; static NAT between address sets of different size is mapped in order and wraps around. |
| `NAT_ZONES` | A or R | To Check Point: the rule applied to some zones only and is written without them. To Sophos or a Device Manager, whose NAT rules match interfaces: the interfaces of a zone are not known, and the rule is written for any interface; name them with `--interface-map`. R where the zone was the only limit: a source NAT towards one zone now translates traffic towards every zone. |
| `NAT_LINKED` | I or A | Sophos source: a linked NAT rule has no match of its own. It is written with the zones, addresses and services of its firewall rule. A when that rule has exclusions, users or a schedule, which a NAT rule cannot say: the NAT rule then applies to more traffic than it did. |
| `NAT_LINKED_ABOVE` | A | Sophos source: a linked NAT rule translates only what its own firewall rule lets through. As a rule of its own it also applies to traffic of the same zones, addresses and services that a rule higher up lets through. |
| `NAT_INTERFACE` | A or R | Sophos source: a NAT rule matches interfaces. The interface became its zone, which holds other interfaces as well; or the input does not say which zone the interface is in, and the rule was read for any zone. R where the interface was all that limited the rule. Export the zones and interfaces with the rules. Management Center source: a NAT rule names an interface group. It was read as the zones of its interfaces (A when those zones hold other interfaces too), or for any zone when the input does not show the group, its interfaces and their zones (R). Device Manager source: the interface of a NAT rule became its zone, which holds other interfaces as well (A); or the input does not hold the interface or its zone (a partial listing, a file written for an import), and the rule was read for any zone (R). |
| `NAT_LINKED_INACTIVE` | I | Sophos source: a NAT rule linked to a firewall rule that is disabled, or that blocks. It translated nothing, and is converted disabled. |
| `NAT_LOAD_BALANCING` | A | Sophos source: a rule that spreads connections over several servers by a method other than round robin, or with a health check. It is converted as a translation that picks one of the addresses per connection. |
| `NAT_DESTINATION_ZONE` | A or R | To Sophos: the rule translated the destination of traffic that was on its way to one zone. A Sophos NAT rule cannot say that, and applies to its destination addresses in whatever zone they lie. R when the rule names no destination address: it now translates traffic to every destination. Not raised for a rule that names a few addresses, where the zone adds nothing. |
| `NAT_OUTBOUND_INTERFACE` | A | Sophos source: a rule that translates the destination and is limited to an outbound interface. That limit is not converted. |
| `NAT_INTERFACE_OVERRIDE` | R | Sophos source: the rule translates the source to other addresses for some outbound interfaces. Only its general translation is converted. |
| `NAT_IP_VERSION` | A or I | To Sophos: a NAT rule is for one IP version. The addresses of the other version in its lists were left out. To a Management Center or a Device Manager (I): a rule that names no address at all is written for IPv4. |
| `NAT_DYNAMIC_IP` | A | To Sophos: translation to a pool without port translation becomes source NAT that shares the addresses, with port translation. |
| `NAT_ZONE_ASSUMED` | A | To PAN-OS: the source rule names no destination zone; the zone given with `--target-nat-zone` was used. |
| `NAT_GROUP` | I | To Check Point: a group was created, because a NAT rule cell holds one object. |
| `NAT_ADDRESSES`, `NAT_SERVICE`, `NAT_RANGE` | R, skipped (`NAT_RANGE`: A) | To Sophos (`NAT_ADDRESSES`): source and destination of the rule share no IP version. To iptables: the rule needs static IPv4 addresses and a TCP, UDP or SCTP service. DNAT to a range picks an address per connection. To ASA, a Management Center or a Device Manager: the rule needs static addresses of one IP version per object, and a service of at most 16 TCP or UDP ports or ranges without source ports (on an ASA also SCTP; on a Device Manager single ports only). |
| `NAT_ANY_DESTINATION` | R | To iptables: the rule translates traffic to every destination; the security rules were not adjusted to the translated address. |
| `NAT_INPUT_INTERFACE` | A or R | To iptables: source NAT is done in `POSTROUTING`, which cannot match the interface the traffic came in on. R when that was the rule's only limit. |
| `NAT_OUTPUT_INTERFACE` | A | To iptables or FortiOS: a rule that translates destination and source. After the destination translation the traffic leaves by another interface than the rule names, so the source translation is written for every interface. |
| `NAT_AFTER_DNAT` | A | The same kind of rule. Its source translation is matched after the destination was translated, and cannot be tied to the original destination: it also applies to traffic from the same sources that is sent to the translated address directly. iptables output avoids this where the original destination is an address or network (`--ctorigdst`); FortiOS central SNAT cannot. |
| `AUTOMATIC_NAT_IN_GROUP` | R | Check Point source: a manual NAT rule names a group that holds an object with automatic static NAT. In the converted rule the group also matches the translated address; whether Check Point does is not known. |
| `AUTOMATIC_NAT_SHAPE` | R | Check Point source: an automatic NAT rule that does not name the same object in its original and translated column. It was read as it stands. |
| `NAT_DESTINATION`, `NAT_DESTINATION_SIZE`, `NAT_PORT` | R, skipped | To FortiOS: the destination NAT cannot become a virtual IP: it needs one IPv4 address or range on each side, of equal size, and for a port translation a service with one protocol and one port or range. To ASA, a Management Center or a Device Manager: one static address object on each side; a port translation needs a service with single ports. |
| `NAT_POOL` | R, skipped | To FortiOS or iptables: the translated address is not a static IPv4 address, or not exactly one address or range. To ASA, a Management Center or a Device Manager: it is not a static address. |
| `NAT_IPV6` | R or I, skipped | To FortiOS: the rule is not IPv4 (R). With `--to ip6tables`: NAT rules are written for IPv4 only (I, on every NAT rule). |
| `NAT_DISABLED` | I | A NAT rule that is disabled in the source. To FortiOS no virtual IP is created for it (skipped); to iptables it is written as a comment line. |
| `NAT_OVERLAP` | R | FortiOS source: another policy passes overlapping traffic without NAT, for other services. NAT rules do not match on service, so that traffic would be translated. Add a no-NAT rule or narrow this one. |
| `NAT_EXEMPTION` | A | FortiOS source: a no-NAT rule was added for an earlier policy that passes this traffic untranslated. It applies to all services. |
| `NAT_SERVICE_DROPPED` | A or R | To FortiOS: the rule translated one service only; the virtual IP (A) or central SNAT entry (R) applies to all. |
| `NAT_SOURCE_DROPPED` | A | To FortiOS: the destination NAT applied to some sources only; the virtual IP applies to all. |
| `NAT_BIDIRECTIONAL` | I, A or R | Bi-directional static NAT is written as two parts: a central SNAT entry plus a virtual IP on FortiOS, an SNAT and a DNAT rule on iptables, two NAT rules on Check Point and on Sophos (`name` and `name-in`). R when the inbound half could not be written. |
| `NAT_STATIC_RANGE` | A | To FortiOS: static NAT of several addresses becomes a one-to-one pool, which does not promise the same translated address per host. To Sophos: it becomes source NAT to a range, which does not promise it either. |
| `NAT_INTERFACE_ADDRESS` | A | To PAN-OS or Check Point: source NAT to an interface address was written with the address that interface has in the backup. Use `--interface-map` (PAN-OS) or `--target-gateway` (Check Point) to follow the interface instead. ASA, Management Center or Device Manager source: a rule that publishes a port on the address of an interface is converted with the address the interface has in the input; to an ASA, a Management Center or a Device Manager it is written as "the interface" again, and the finding is withdrawn. |
| `VIP_REVERSE_NAT` | A | FortiOS source: a static virtual IP also translates sessions the mapped host opens, when the outgoing policy has NAT. That direction is not converted. |
| `NAT_MERGED` | I | FortiOS source: several policies had identical source NAT and share one rule. |
| `NAT_REFLECTION` | I | pfSense source: the port forward has NAT reflection, so it also applies to what arrives on the inside interfaces named in the finding. It is converted for those interfaces too. |
| `NAT_REFLECTION_PROXY` | R | pfSense source: NAT reflection in proxy mode. Inside clients that use the outside address are answered by a proxy on the firewall, which needs no rule. Not converted. |
| `NAT_STATIC_PORT` | A | pfSense source: outbound NAT to the address of the interface with *Static port*: converted as port address translation, which may change the port. To pfSense: translation to a pool without port translation is written with *Static port*, which keeps the port and still shares the addresses between connections. |
| `NAT_SOURCE_PORT` | I | pfSense source: outbound NAT translates the source port to a given port, which the model has no place for. |
| `NAT_IPV6_ALSO` | I | pfSense source: an outbound NAT rule without IP version, source or destination is written by pfSense for IPv4 and for IPv6. It is converted for IPv4; IPv6 NAT is not converted. |
| `NAT_AUTOMATIC_SOURCES` | A | pfSense source: automatic outbound NAT also translates what comes from the clients of the PPPoE server or through IPsec VTI tunnels, whose addresses are not in the configuration. The converted rule does not hold them. |
| `NAT_REFLEXIVE` | A | SonicWall source: a reflexive NAT policy has a mirror image, which SonicOS adds by itself. It is converted as a rule of its own, built as the mirror is assumed to be: sources and destinations swapped with their translations. |
| `RULE_SPLIT` | I | To PAN-OS: one rule per destination zone. To SonicWall: one NAT policy per pair of interfaces. |

### Objects

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `UNSUPPORTED_ADDRESS`, `INVALID_ADDRESS` | R | An address type that is not converted (wildcard mask, geography, dynamic, a Check Point access role, group with exclusion or updatable object, a Sophos MAC host, country group, host name with a wildcard or system host), an object that is not in a Check Point export or in the JSON of a Cisco manager in full (named, without its value), an object of a Cisco manager of a kind that has no addresses to read (a country, a dynamic object), or a value that cannot be read. Emitted as a placeholder; rules using it are disabled. A Device Manager gets no placeholder: the rules are left out. |
| `UNSUPPORTED_VIP` | R | A virtual IP that is not a static NAT (load balancing and others) or cannot be read. |
| `GROUP_EXCLUDE` | R | A FortiOS address group with excluded members. |
| `UNSUPPORTED_GROUP` | R | A group that holds itself, directly or through other groups: no platform takes one. Groups nested more than 64 deep are not followed either. ASA source: an object group with a member that could not be read, or object groups nested more than 64 deep. Management Center or Device Manager source: a group with a member, or a field, that could not be read. Emitted as a placeholder; rules using it are disabled. |
| `UNDEFINED_REFERENCE` | R | A rule names something that is not an object in the input: a region, an external dynamic list, a missing object. Emitted as a placeholder. |
| `UNSUPPORTED_SERVICE` | R | A service that cannot be converted: a proxy service, one limited to a destination address, an unreadable port list, a Check Point application or RPC object, an object that is not in the export in full. To Sophos: SCTP ports, an ICMP type or code that is not on the list of a Sophos service, an IP protocol Sophos has no name for. To a Management Center or a Device Manager: SCTP ports, an ICMP code without a type, port 0 alone; to a Device Manager also an IP protocol or an ICMP type or code it has no name for (among them IP in IP, protocol 4, and IPv6 in IP, protocol 41). |
| `DUPLICATE_NAME` | R | Sophos source: the input defines a name twice. The last definition was kept. |
| `GROUP_SPLIT` | I | To Sophos: IPv4 hosts, IPv6 hosts and host names are kept in groups of their own, and groups hold hosts only. A group of the source became `name`, `name_v6` and `name_fqdn` as far as it has members of each kind. To a Management Center or a Device Manager: a network group holds no FQDN objects. The group is written without them, and every rule that uses the group names them next to it. |
| `SERVICE_SPLIT` | I | To Sophos: a service holds one kind of protocol. A service with several became `name-tcpudp`, `name-ip`, `name-icmp`, `name-icmpv6` and a service group `name`. To a Management Center or a Device Manager: a port object holds one port or range of one protocol. A service with several became a port group `name` of objects such as `tcp-80` and `tcp-443`. |
| `PROTOCOL_NAME` | I | To Sophos: an IP protocol is written by name, and the name is the keyword of the IANA registry. For the protocols the Sophos documentation does not show, check that the import took the service. |
| `ICMP_CODE` | I | To a Device Manager: an ICMP type for which it has no codes was given with code 0 (ping, type 8 code 0, as several platforms write it). It is written as the type alone: 0 is the only code such a type has. |
| `PORT_ZERO` | I | To Sophos, a Management Center or a Device Manager: a port list that starts at port 0. No connection has port 0, and a service of these platforms starts at port 1: it is left out. |
| `SYSTEM_HOST` | I | Sophos to Sophos: a system host of the firewall (`#Port1`). It is referred to by name and must exist on the target. |
| `AUTOMATIC_NAT` | I or R | Check Point source: the object has automatic static NAT. As on Check Point, rules and groups that name it also match its translated address, written as a second object `<name>_valid_address`. R when the NAT settings could not be read. |
| `GATEWAY_OBJECT` | A | Check Point source: a gateway or cluster object. It is converted as its main address; a Check Point target refers to it by name and does not create it. |
| `PROTOCOL_SIGNATURE` | A | Check Point source: the service also matches on the signature of its protocol. |
| `EXISTING_OBJECT` | I | Check Point to Check Point: an object the management server has already (predefined, or a gateway). It is referred to by name and not created. Management Center to Management Center, Device Manager to Device Manager: an object the manager comes with (`any-ipv4`, `HTTPS`, ...). The script for a Management Center checks that each is there before it creates anything. |
| `PREDEFINED_OBJECT` | I | To a Management Center or a Device Manager: an object for every IPv4 or every IPv6 address is not created; the object the manager has for that, `any-ipv4` or `any-ipv6`, is used. Management Center or Device Manager source: the input names one of those two objects and does not hold it (a partial export). It was read as what it is on every manager. |
| `POOL_TYPE` | A | A FortiOS IP pool type other than overload or one-to-one, converted as port address translation. |
| `FACTORY_DEFAULT` | I | A FortiOS default service was referenced but not defined in the input; the factory definition was assumed. |
| `RENAMED` | I | The name was changed: characters or length the target rejects, a collision, or a name the target predefines. |

### Notes for the whole policy

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `CENTRAL_NAT` | R | To FortiOS: NAT is written as central NAT, which has to be enabled first (section 10). |
| `INTRAZONE_DEFAULT` | R | To FortiOS, Sophos, iptables, ASA, a Management Center or a Device Manager: the source allowed traffic inside a zone by default and the target does not, or (iptables with `FORWARD` policy `ACCEPT`) the other way round. |
| `INTRAZONE_ALLOW` | R | To iptables or ASA: a FortiOS zone with `set intrazone allow`. No rule was written for the traffic between its interfaces. |
| `INTERZONE_DEFAULT` | R | The source allows what no rule matches (a PAN-OS `interzone-default` override, an iptables `FORWARD` policy `ACCEPT`, a Check Point layer whose implicit cleanup accepts, an access control policy of a Cisco manager whose default action is not *Block*). That is not carried over; only iptables output keeps it, as the chain policy, ASA output, as a final `permit ip any any` in the global access list, and pfSense output, as a rule that passes everything at the end of every interface. |
| `ZONES_WITHOUT_INTERFACES` | R | To FortiOS: zones were created empty. Assign interfaces or use `--zone-map` / `--interface-map`. |
| `ZONES_REQUIRED` | R | To PAN-OS, Check Point, Sophos or a Device Manager: the zones named by the rules must exist on the target and be assigned to interfaces. To a Management Center: the script uses a zone that exists and creates one that does not, empty: it matches no traffic until interfaces are put in it. |
| `INTERFACES_REQUIRED` | R | To iptables or ASA: zones are written as interface names. Map each zone to its interface with `--zone-map`. For an ASA the note also states what the access lists count on: that the ASA has no other interfaces than the policy names, and does not send traffic back out of the interface it came in on (section 8). To a Device Manager: the NAT rules name interfaces by their logical name and as physical interfaces; map the names with `--interface-map`, and change the type in the file where one is a subinterface, an EtherChannel or a VLAN interface. |
| `INTRAZONE_ALLOW_MERGED` | R | To PAN-OS or Check Point: `--zone-map` merges a zone that allows intrazone traffic with another one; no allow rule was written for it. |
| `NAT_ORDER` | A | To PAN-OS, Check Point or Sophos, from FortiOS, iptables, ASA, or Check Point automatic NAT rules: the source applies a destination NAT rule and a source NAT rule to one connection, the target one NAT rule only (section 8). To ASA from those sources: a destination NAT without a port is written as a rule that leaves the source alone, with the same effect. |
| `TABLE_NOT_CONVERTED` | R | FortiOS source: a table such as `firewall policy6` or `firewall local-in-policy` has entries and is not converted. iptables source: the `mangle`, `raw` or `security` table has rules. ASA source before 9.0: `ipv6 access-list` lines; the result has no IPv6 rules. |
| `SUSPICIOUS_QUOTING` | R | FortiOS source: a quoted value runs over lines that look like configuration. An unescaped quote may have hidden entries; check the line given. |
| `NO_HIERARCHY` | R | Panorama source without `<readonly>`: parent device groups could not be found. |
| `INTRAZONE_DENY_ADDED` | I | To PAN-OS: `fwshift-intrazone-deny` was appended (section 8). |
| `EXISTING_OBJECTS` | I | To FortiOS, ASA, Sophos or a Device Manager: objects are created by name and change existing ones of the same name; an ASA object group that exists gets the new members added to its own. |
| `PANORAMA_SOURCE` | I | Reminder of what a Panorama export does not contain. |
| `PRUNED` | I | `--prune-unused` left out this many objects. |
| `HIT_COUNTERS` | I | With `--hits` (or a configuration that carries hit counts): which counters were read, how many rules they counted, and the rules they count that the policy does not have (section 13). |
| `USAGE_STORE` | I | With `--usage-store`: the window that was used, and how many connections of it were attributed to a rule of the policy (section 15). |

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
| `LOG_EVERY_PACKET` | I | Source: a `LOG` rule ahead of the rule that accepts established connections (or in a ruleset without one) logs packets of connections already open. `fwshift usage` leaves out the TCP packets that open no connection and counts the lines of other protocols as possible only (section 15). |

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
| `HITS_NOT_READ` | I | Source: rules have a `hits` field without a whole number in `value`. The audit says nothing about the use of those rules. |
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

Notes that only a Sophos Firewall source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `NO_RULES` | R | Source: the input holds no firewall rule and no NAT rule. Was it exported without them? |
| `RULE_ORDER` | R | Source: rules are placed after or before a rule that the input does not hold above them. They were read in the order of the file: check it against the firewall. |
| `ELEMENTS_NOT_READ` | I | Source: elements of rules that FWShift does not know and that do not look like a match criterion. What they say is not converted. (One that does look like a criterion makes its rule unsupported instead.) |
| `SOPHOS_LOAD` | R | Target: how to import the output; that its rules land below the rules the firewall has, where an existing rule (the default source NAT rule of a new firewall) comes first; and that an import can stop at an object the firewall does not take (section 10). |
| `IP_VERSION_SPLIT` | I | Target: this many rules match both IP versions and were written twice; the name of the IPv6 rule ends in `_v6`. |
| `INTRAZONE_ALLOW_ADDED` | I | Target: rules were appended for the zones that allow traffic between their own interfaces on the source. |

Notes that only a pfSense source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `RULE_NOT_LOADED` | R | Source: rules pfSense itself does not load, because something they name cannot be resolved (an alias that is not there, an interface that is not enabled, a port range that runs backwards). They decide nothing on the firewall and are not converted; the note names each with its reason. A rule pfSense loads and FWShift cannot read is kept and written disabled instead. |
| `RULE_ORDER_VERSION` | R | Source: rules of two interface groups that share an interface are not in the file in the order of their groups. pfSense up to 2.7 evaluates them in the order of the file, later versions group by group; they were read as the version in the file says (section 3). |
| `FLOATING_LAST_MATCH` | I | Source: floating rules that are not *quick* decide only where no rule of an interface matched, and of several the last one. They stand behind the rules of the interfaces, the last one first. |
| `FLOATING_OUT_PASS` | I | Source: floating rules that pass traffic leaving by an interface decide nothing for forwarded traffic, which leaves when the rules of its arrival interface passed it. Not converted. |
| `MATCH_RULE_SKIPPED` | I | Source: a rule of type *match* marks or shapes traffic and decides nothing. Not converted. |
| `IPV6_NOT_ALLOWED` | I | Source: *Allow IPv6* is off, so the firewall drops all IPv6 traffic. Rules for IPv6 or both versions were read for IPv4 only. |
| `FILTER_DISABLED` | R | Source: packet filtering is switched off: the firewall routes everything and translates nothing. The rules were converted as they stand. |
| `BOGONS_NOT_CONVERTED` | R | Source: *Block bogon networks* is set on an interface. The list it uses is downloaded, not in the configuration, and nothing is converted for it. |
| `BRIDGE_NOT_CONVERTED` | R | Source: interfaces are bridged. Where a bridged packet is filtered is a system setting; the rules were read as those of routed interfaces. |
| `CAPTIVE_PORTAL` | R | Source: a captive portal lets only clients that logged in through its interfaces. Not converted. |
| `NPT_NOT_CONVERTED` | R | Source: IPv6 prefix translation (NPt) rules are not converted. |
| `PFSENSE_AUTOMATIC_RULES` | I | Source: the rules pfSense puts before those of the configuration (antispoof, link-local addresses, port 0, the ICMPv6 that IPv6 needs, anti-lockout and rules for its own services) are not converted, and rules for the firewall itself are rules like any other in the model. |
| `PFSENSE_RESTORE` | R | Target: how to restore the output (section 10). Each restore of an area replaces that area of the firewall, with what it does to outbound NAT and the settings that are part of it. |
| `SELF_EXCLUDED` | I | Target: on pfSense the rules of an interface are also the rules for traffic to the firewall itself. A rule that passes traffic to any destination is written for "any but *This Firewall*", so that it does not open the firewall; a rule that names an address of the firewall still reaches it. |
| `EGRESS_IMPLIED` | I | Target: the source rules name no interface traffic leaves by either (an ASA source); the destination zones worked out for them were left out again. |
| `SCHEDULES_NOT_WRITTEN` | I | pfSense to pfSense: schedules are not part of the three areas the file holds, so rules with a schedule are written disabled. |
| `INTERFACES_REQUIRED`, `INTERFACE_NAME`, `ZONE_NETWORK_UNKNOWN`, `ZONE_NETWORK_GAP` | | Target: as for an ASA. A zone that is no interface of pfSense keeps its name, which pfSense takes for an interface group of that name. |

To pfSense, the NAT findings `NAT_INTERFACE`, `NAT_IPV6`, `NAT_SERVICE`,
`NAT_ADDRESSES`, `NAT_DESTINATION`, `NAT_PORT`, `NAT_POOL`,
`NAT_BIDIRECTIONAL`, `NAT_INPUT_INTERFACE`, `NAT_OUTPUT_INTERFACE` and
`NAT_AFTER_DNAT`, and the rule findings `ICMP_CODE`, `ICMP_TYPE`,
`INTERFACE_NAME`, `RULE_TYPE`, `EGRESS_INTERFACE`, `EGRESS_BY_NETWORKS` and
`EGRESS_NO_ADDRESS`, mean what they mean for
the other targets; the message says what pfSense cannot hold, and section 8
what it can.

Notes that only a SonicWall source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `SONICWALL_FORMAT` | I | Source: the settings export is not documented beyond its encoding; what was read, and that what the parser does not know of a rule is not read. |
| `DEFAULT_OBJECT` | I | Source (on the object): an address object or service SonicOS has by itself and the export does not list, worked out from the interfaces of the export or taken from the defaults of SonicOS. |
| `ZONE_TYPE_ASSUMED` | I | Source: the security type of a zone was read from a code of the export whose meaning comes from the published readers of the format. It decides the default rules of the zone. |
| `DEFAULT_RULES_UNKNOWN` | R | Source: pairs of zones without a default rule in the export, of security types for which the default of SonicOS is not documented. Traffic between them that no rule matches is taken to be denied. |
| `OBJECTS_NOT_READ` | R | Source: a table of address objects the parser does not read (IPv6, MAC). Rules that name such an object are disabled. |
| `NO_RULES` | R | Source: the export holds no access rule and no NAT policy. |
| `SONICWALL_LOAD` | R | Target: how to load the commands (section 10), and which parts of them are not in the documentation FWShift was written from. |
| `DEFAULT_DENY_ADDED` | I | Target: a rule that denies was added at the end of each pair of zones and IP version, because SonicOS allows some pairs by itself and the source did not. |
| `ICMP_AS_DEFAULT` | I | Target (on the service): ICMP echo request is written as the default service `Ping` of SonicOS. |
| `ZONES_REQUIRED`, `EXISTING_OBJECTS`, `IP_VERSION_SPLIT`, `GROUP_SPLIT`, `SERVICE_SPLIT`, `NEGATION_EXPANDED`, `NEGATION_NOT_STATIC`, `NAT_INTERFACE`, `NAT_OUTBOUND_INTERFACE`, `NAT_ZONES`, `NAT_DESTINATION_ZONE`, `NAT_DYNAMIC_IP`, `NAT_BIDIRECTIONAL` | | As for Sophos Firewall and ASA: a SonicOS address group and rule are of one IP version, a service object of one protocol and range, and a NAT policy matches one inbound and one outbound interface. |

Findings and notes that only a WatchGuard source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `WATCHGUARD_FORMAT` | I | Source: the configuration file of Policy Manager is not documented by WatchGuard; the elements read are those the published readers of the format agree on. |
| `POLICY_ORDER_AUTOMATIC` | R | Source: the configuration orders its policies automatically, or does not say. The Firebox then orders them itself, by how specific they are, and the order of the file was read. Switch to manual order in Policy Manager and save the file again, or check the order of the result against Policy Manager. |
| `POLICY_SPLIT` | I | Source (on the rule): the From and To lists of a policy name members of several interfaces. It became one rule per pair of From and To members, which together match what the policy matched. |
| `NAT_NOT_READ` | R | Source: network dynamic NAT, 1-to-1 NAT and the NAT settings of a policy are not read, because where the file keeps them is not known. Static NAT actions in the To list of a policy are read. Traffic those translate is in the result untranslated. |
| `WATCHGUARD_LOAD` | R | Target: the output is the policy part of a configuration file, not a file to restore as it is; how to merge it (section 10), and that the words for the action of a policy are assumed. |
| `NAT_NOT_IN_POLICY` | R | Target (on the rule): the rule allows the destination of a NAT rule, but for other services, zones or sources than the NAT rule translates, or another NAT rule comes first for that traffic. On a Firebox the translation is part of the policy; this policy names the public address without translating it. |
| `NAT_ZONE_DROPPED` | A | Target (on the rule): the rule carries a static NAT action, which names the public address with no interface to the server. The policy allows the translated traffic to the server wherever it is, not only in the zone of the rule. |
| `NAT_NO_POLICY` | I | Target (on the NAT rule): no rule allows exactly the traffic the NAT rule translates. The static NAT action is written, and no policy uses it. |

Findings and notes that only a Barracuda source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `BARRACUDA_FORMAT` | I | Source: what was read from the answers of the REST API, and that a key of a rule, an object or an entry the parser does not know makes it unusable: the API is documented by examples only. |
| `RULES_JOINED` | I | Source: the input holds several lists of rules; they were read one after the other, as pages of one list. |
| `ANSWERS_NOT_READ` | R | Source: JSON documents of the input that are no rules and no objects the parser knows. |
| `OBJECTS_MISSING` | R | Source: objects the rules name are not in the input. The rules that name them are not used; fetch the objects and add them (section 3). |
| `CONNECTION_NOT_READ` | R | Source: rules whose connection object translates the source address. Source NAT is not read; the rules are. |
| `ICMP_LIMITS` | A | Source (note, and on each rule that uses such a service): a service object limits the size or rate of ICMP echo requests; the limits are not converted. |
| `INTERFACE_SPLIT` | I | Source (on the rule): the source of a rule holds entries of several interfaces. It became one rule per interface, the interfaces as zones. |
| `BIDIRECTIONAL_SPLIT` | I | Source (on the rule): a bi-directional rule became two rules, the second one with source and destination swapped. |
| `DYNAMIC_RULE` | A | Source (on the rule): a dynamic rule, which the firewall switches on and off at run time, read as it stood when the input was saved (approximated for an active rule that allows). |
| `RULE_EXPIRES` | A | Source (on the rule): a blocking rule that expires blocks for good once converted. An allowing rule that expires is not used. |
| `BARRACUDA_LOAD` | R | Target: how the script works (section 10): objects, then the rules deactivated, then activated in order; which keys of the API are assumed. |
| `BLOCK_RULE_INACTIVE` | R | Target: the rules FWSHIFT-BLOCK and FWSHIFT-BLOCK-v6 that block what no converted rule matches are created deactivated. Until they are activated, the rules the firewall has below them decide that traffic. |
| `ZONE_BY_NETWORKS` | I/A | Target (on the rule): a zone of the rule is written as the networks given for it with `--zone-network` (approximated when addresses that lie in no network given were left out of an allowing rule). |
| `ZONE_NETWORK_MISSING` | R | Target (on the rule): a rule that allows names a zone that has neither networks (`--zone-network`) nor, for its source, an interface (`--interface-map`). A rule of the firewall names no zone: the rule is deactivated. |
| `ZONE_WIDENED` | A | Target (on the rule): a blocking rule names a zone the converter cannot express; it blocks its traffic in every zone. |
| `INTERFACES_REQUIRED`, `INTERZONE_DEFAULT`, `NEGATION_EXPANDED`, `IP_VERSION_SPLIT`, `NO_COMMON_FAMILY`, `RULE_TYPE`, `RESET_ACTION`, `UNSUPPORTED_SERVICE`, `NAT_NOT_CONVERTED` | | As for the other targets: a rule of the firewall is of one IP version, has no negation and names no zones; NAT is not written. |

Findings and notes that only a Juniper source or target raises:

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `JUNOS_FORMAT` | I | Source: what was read; policies are looked up after static and destination NAT on an SRX, and were brought back to the original destination (`NAT_DESTINATION_REWRITTEN` on the rules where that changed something). |
| `PREDEFINED_APPLICATIONS` | I | Source: the predefined applications the policies use, taken from FWShift's table of them. |
| `HOST_POLICIES` | I | Source: policies for the zone `junos-host`, traffic to and from the SRX itself, are not read. |
| `PARTS_NOT_READ` | R | Source: parts of the security configuration the parser does not read (logical systems, tenants, and others it names). |
| `OBJECTS_MISSING` | R | Source (as for Barracuda): names the policies or NAT rules use and the configuration does not define; the rules that use them are not used. |
| `JUNOS_LOAD` | R | Target: how to load the set commands (section 10), where new policies land, and what is assumed. |
| `DEFAULT_PERMIT` | R | Target: the source allows what no rule matches, written as `default-policy permit-all`, which applies to the whole SRX. |
| `ZONES_EXPANDED` | I | Target (on the rule): a rule for every zone is written for each pair of the zones the policy knows; other zones of the SRX do not get it. |
| `NAT_STATIC` | I | Target (on the NAT rule): a destination NAT and the source NAT that undoes it for the way back, written together as one static NAT rule. |
| `ZONES_REQUIRED`, `INTERZONE_DEFAULT`, `RULE_SPLIT`, `NEGATION_EXPANDED`, `NEGATION_NOT_STATIC`, `RESET_ACTION`, `NAT_AFTER_DNAT`, `NAT_BIDIRECTIONAL`, `NAT_EXEMPTION`, `RULE_TYPE_EMPTY` | | As for the other targets: a policy is for one pair of zones, an application of one protocol and port range per term, a NAT rule set for one zone or pair of zones. |

Notes that only a Cisco Secure Firewall source or target raises (Management
Center, Device Manager):

| Code | Sev. | Meaning and what to do |
|---|---|---|
| `RULES_NOT_EXPANDED` | R | Source: rules are in the input by name only, as the API lists them without `expanded=true`. They are kept in their place and not converted (section 3). |
| `EXPORT_INCOMPLETE` | R | Source: the manager says it has more access rules, prefilter rules or NAT rules than the input holds as rules FWShift could read: pages are missing (section 3), or the list holds items that are not rules of that kind. Or the input holds the access control policy and no list of its rules; or one of the saved answers is an error of the manager (a token that ran out) instead of what was asked for. In each case rules are missing, and the rules that are there now decide traffic the missing ones decided. |
| `DEFAULT_ACTION_UNKNOWN` | R | Source: the input does not hold the access control policy itself, or its default action is one FWShift does not know. The default action was taken to block. A file written for the import of a Device Manager is read that way too: it holds what is added, not the policy. |
| `INHERITANCE_UNKNOWN` | R | Source: nothing in the input says whether the access control policy inherits from another: not the policy itself, not its inheritance settings, not the rules listed with it. If it does, the mandatory rules of the parent come before the rules that were read and its default rules after them, and they are not in the result. Fetch `policy/accesspolicies/<id>/inheritancesettings` as well (section 3). |
| `PARENT_POLICY_MISSING` | R | Source: the access control policy inherits from another whose rules are not in the input. Its mandatory rules come before the rules that were read and its default rules after them. |
| `RULE_SECTIONS_UNKNOWN` | R | Source: the policy inherits, or is inherited from, and its rules do not say whether they are mandatory or default rules, which decides where the rules of the other policy go. They were read as mandatory rules. |
| `PREFILTER_MISSING` | R | Source: the access control policy uses a prefilter policy whose rules are not in the input. They come before the access rules. |
| `PREFILTER_DEFAULT_UNKNOWN` | R | Source: the input does not hold the prefilter policy itself, so it is not known whether it blocks tunnel traffic that none of its rules match or hands it to the access rules. It was read as handing it on. |
| `PREFILTER_ASSUMED` | I | Source: the rules of one prefilter policy are in the input and the access control policy, which says which prefilter policy it uses, is not. They were read as its prefilter rules. |
| `PREFILTER_NOT_READ` | R | Source: the input holds the rules of several prefilter policies and not the access control policy that says which one it uses. None was read. |
| `OBJECT_OVERRIDES` | A | Source: objects that allow overrides can have another value on a device than the one the Management Center holds. The values of the Management Center were converted. |
| `FMC_LOAD` | R | Target: the output is a script that creates objects, a new access control policy and a new NAT policy, and assigns them to no device (section 10). |
| `FDM_LOAD` | R | Target: the output is a file for a configuration import; what its first object must say, where its rules land and that nothing is in force before a deployment (section 10). |
| `ZONE_RENAMED` | I | Source: a zone is named `any`. Target: a zone name that cannot be an object name was changed; choose another with `--zone-map`. |
| `INTRAZONE_ALLOW_ADDED` | I | Target: rules were appended for the zones that allow traffic between their own interfaces on the source. |
| `FQDN_DNS` | I | Target: FQDN objects need name resolution on the device. |

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
* Sophos Firewall keeps a rulebase per IP version, and "any" in each of them
  is any address of that version. See *Sophos Firewall* below.

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

Sophos Firewall has *exclusions*, which are one condition for the whole rule
and not a negation per field. What that means in both directions is described
under *Sophos Firewall* below.

An access rule of a Cisco Secure Firewall cannot negate either. A negated
address list is written as the addresses it leaves (`NEGATION_AS_ADDRESSES`);
a rule with a negated service, or with a negated list that holds a host name,
is not converted (`NEGATION`).

### Zones and interfaces

Zone and interface names are carried over unchanged; rename them with
`--zone-map`. To FortiOS, zones are created, empty unless `--interface-map`
names their interfaces; a zone you map onto an existing name is not created.
To PAN-OS, to Sophos Firewall and to a Device Manager, zones are not created:
they must exist. The script for a Management Center creates the zones that
are missing, empty.

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

*To Sophos Firewall,* which drops traffic between the interfaces of a zone
unless a rule allows it, the difference is reported (`INTRAZONE_DEFAULT`). A
zone that allowed it on the source (FortiOS `set intrazone allow`) gets a rule
of its own below all others (`INTRAZONE_ALLOW_ADDED`).

*To a Cisco Secure Firewall,* whose access rules decide about traffic between
the interfaces of a zone as about any other, the same: the difference is
reported, and a zone that allowed its own traffic on the source gets a rule
below all others. A policy read from a Management Center or a Device Manager
has one default action for everything; converted to another platform it is
both defaults.

A source that allows what **no** rule matches (an iptables `FORWARD` chain
with policy `ACCEPT`, a Check Point layer whose implicit cleanup accepts, a
PAN-OS `interzone-default` override) keeps that only in iptables output. The
other targets end in their own deny, and the report says so
(`INTERZONE_DEFAULT`); ASA output ends its global access list in
`permit ip any any` instead, pfSense output every interface in a rule that
passes everything, and the report says that. The access control
policy the script for a Management Center creates blocks by default, and an
import does not change the default action of a Device Manager.

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
| Sophos Firewall (18 and later) | the original (pre-NAT) address, and the zone the traffic ends in | one: the first that matches; it can translate source and destination |

What is said above for FortiOS holds for iptables and ASA, and what is said
for PAN-OS holds for Check Point and Sophos Firewall. A rule for *part* of a translated network
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

* **From FortiOS, iptables or ASA to PAN-OS, Check Point or Sophos Firewall.** A connection that got
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
* An **access role** in the source of a rule is its networks for its users:
  the networks go into the source, the users (Active Directory, LDAP or
  internal groups, identity tags; "all identified users" as `known-user`)
  into the rule's users (`ACCESS_ROLE`). A cell that holds roles of different
  users, or roles next to plain addresses, becomes one rule per set of users
  and one for the plain addresses, in place and with the same action
  (`PLC access`, `PLC access (operators)`, ...): together they match what the
  cell matched, and the networks of one role never meet the users of another.
  A role that also names machines or a remote access client, a role in a
  destination or a negated source, and a role whose content is not in the
  export (section 3) are not converted: their rules are written disabled.
  Inside an inline layer the users of the rule applying the layer and of the
  rule inside must agree, or the rule is written disabled.
* Each rule keeps its **uid** (and for a rule of an inline layer the uid of the
  rule applying it, and the uids of every rule on the way), its
  **install-on** gateways and its **hit count** in the model (`--to json`:
  `source_ids`, `targets`, `hits`). The audit reads the hit counts (section
  13); nothing of it is written to a target.
* Not converted, and reported on the rules that use them: access roles that
  the model cannot hold (above), groups with exclusion, wildcard, dynamic and updatable objects, application and
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

### Sophos Firewall

**What is read**

* The firewall rules, in the order the firewall evaluates them. Each IP
  version has a rulebase of its own. An export lists the rules in order; a
  file written for the API can place a rule at the top, at the bottom, or
  before or after another one, and is read as the firewall would add the rules
  one by one (`RULE_ORDER` when the other rule is not in the file). Rule
  groups only order the display, and are not read.
* **A list that is not in the file is "any".** That is how this format writes
  any zone, any network and any service. Nothing else is read as any: a list
  that is there and empty, a rule without an action, an element FWShift does
  not know that looks like a match criterion, all make the rule unsupported,
  and it is converted disabled. An unknown element that does not look like
  one is counted and reported (`ELEMENTS_NOT_READ`).
* **IP version.** "Any" in a rule of the IPv4 rulebase is `0.0.0.0/0` in the
  model, where a plain `any` is both versions; in an IPv6 rule it is `::/0`.
  A rule with nothing but host names on both sides cannot say which rulebase
  it was in (`IP_FAMILY`).
* **Exclusions.** A rule can exclude source zones, destination zones, source
  networks, destination networks and services. Sophos Firewall skips the rule
  only for traffic that matches **all** the kinds of exclusion the rule has.
  With one kind that is simple: zones are taken out of the zones of the rule,
  addresses out of "any" become a negated list, addresses out of a list
  become the addresses that are left (`EXCLUSION_AS_ADDRESSES`), services out
  of "any service" a negated service. A rule with exclusions of several kinds
  matches whatever escapes *one* of them, so it becomes one rule per kind,
  `name`, `name-2`, ..., each with that one field cut down (`RULE_SPLIT`).
  "Any zone except X" is written as the other zones of the configuration, so
  export the zones (`EXCLUSION_ZONES`). An exclusion of services from a list
  of services is not converted; the rule is disabled. A rule whose exclusions
  take all of it is left out (`RULE_MATCHES_NOTHING`).
* **What a rule does with its traffic.** Web filter, application control,
  intrusion prevention, malware and e-mail scanning and HTTPS decryption are
  reported as security profiles, as for every platform. Traffic shaping and
  DSCP marking are not converted (`HANDLING_NOT_CONVERTED`).
* **Security Heartbeat.** A rule that asks for a health status of the source
  or the destination is a rule for endpoints that report one. That is a
  condition, and no target has it: the rule is converted disabled.
* **What is said twice, or oddly.** A list or an action that a rule gives
  twice, text next to the members of a list, a status that is neither
  `Enable` nor `Disable`: the rule is unsupported. A rule without a position,
  or with one FWShift does not know, is read where it stands in the file
  (`RULE_ORDER`).
* **Users.** A rule that matches known users is read with its users and
  groups. No target converts that match: the rule is written disabled.
* **The firewall itself.** Rules of web server protection (`WAF_RULE`) and
  rules for the zone `LOCAL` are not forwarding rules. Device access is not
  read.
* **Hosts and services.** IP hosts (address, network, range, list), IP host
  groups, FQDN hosts and their groups; services with TCP and UDP ports
  (source and destination), IP protocols by name, ICMP and ICMPv6 by type and
  code. MAC hosts, country groups and host names with a wildcard are not
  converted; a rule that uses one is disabled.
* **NAT rules**, first match, as they are. A NAT rule matches interfaces, the
  model zones: an interface becomes its zone where the export says which zone
  that is (`NAT_INTERFACE` when the zone holds more interfaces, or is not
  known). `MASQ` is translation to the address of the outgoing interface;
  translation to a host is static when one host is translated to one host,
  and port translation otherwise. A destination translation with a translated
  service is a port translation. A rule that translates the destination does
  not say in which zone its original address lies, and the model wants to
  know (a PAN-OS NAT rule names it). Where the interfaces of the export tell,
  because the address lies in the network of one of them, it is that zone;
  otherwise the rule is read without one, and a conversion to PAN-OS asks for
  it (`--target-nat-zone`).
* **Linked NAT rules** have no match of their own. They are read as NAT rules
  with the zones, addresses and services of their firewall rule
  (`NAT_LINKED`). Two things are lost: what a NAT rule cannot say (the
  exclusions, users and schedule of the firewall rule), and that the linked
  rule only translated what *its* firewall rule let through
  (`NAT_LINKED_ABOVE`). A rule linked to a firewall rule that is disabled or
  that blocks translated nothing, and is converted disabled
  (`NAT_LINKED_INACTIVE`).

**What is written**

* An `Entities.xml`: hosts and services first, then the firewall rules, then
  the NAT rules. Zones and interfaces are not written. A zone must exist
  (`ZONES_REQUIRED`); FWShift does not create one, because an import
  overwrites what has the same name, and with a zone that is its device
  access.
* **One rule per IP version.** A rule that matches both is written twice,
  `name` and `name_v6` (`IP_VERSION_SPLIT`). Address lists are split by
  version; a rule whose only services are ICMP is an IPv4 rule.
* **Negation.** One negated field of a rule is one exclusion, which says the
  same. Two negated fields are not two exclusions: Sophos Firewall would skip
  the rule only where both hold. One field stays the exclusion, the others
  are written as the addresses that are left, as address ranges
  (`NEGATION_AS_ADDRESSES`). A negated list with a host name cannot be turned
  round; if more than one field is left like that, the rule is disabled
  (`NEGATION`).
* **Groups** hold hosts only, of one IP version, and host names are grouped
  apart. A group of the source is written out flat and becomes `name`,
  `name_v6` and `name_fqdn` as far as it has members of each kind
  (`GROUP_SPLIT`). An object that is every address of an IP version is not
  written; a rule that names it says "any".
* **Services** hold one kind of protocol. A service with several becomes a
  group of `name-tcpudp`, `name-ip`, `name-icmp` and `name-icmpv6`
  (`SERVICE_SPLIT`). A Sophos service has ports for TCP and UDP only, ICMP
  types and codes from a list, and IP protocols by name: SCTP ports, other
  ICMP types and protocols without a name are not converted, and the rules
  that use them are disabled. A service for every protocol is "any service".
  Port 0 is left out of a port range (`PORT_ZERO`).
* **Names** are kept to letters, digits, space, `.`, `_` and `-`, 50
  characters for an object and 60 for a rule. Names that differ in case only
  are kept apart with a suffix. An object named like a service a Sophos
  Firewall comes with (`HTTP`, `DNS`, `PING`, ...) or like a word of the
  format (`Any`, `None`, `Original`, `MASQ`) is renamed. `--target-prefix`
  puts a prefix in front of every object that is created. A **zone** with
  such a name cannot be renamed by FWShift, and `<Zone>Any</Zone>` is every
  zone: the conversion stops and asks for `--zone-map`.
* **Placeholders.** An object that cannot be converted becomes an FQDN host
  for a name that does not exist (`placeholder1.fwshift.invalid`): it matches
  nothing, and the rules that use it are disabled.
* **Order.** The first rule of each IP version is placed at the bottom of what
  the firewall has, and every further rule after the one before it. The order
  then does not hang on how the file is read, and a rule that is not taken
  stops the rules after it instead of letting them move up.
* **NAT rules** are written in order, for IPv4 unless all their addresses are
  IPv6. Their interfaces come from `--interface-map`, or, Sophos to Sophos,
  from the zones of the source. Where the interfaces of a zone are not known
  the rule is written for any interface (`NAT_ZONES`): give the map. A rule
  that translates the destination gets "any" as its outbound interface, as
  Sophos asks; where the source limited such a rule to traffic towards one
  zone and the rule names no address, or many, that is a rule for more
  traffic (`NAT_DESTINATION_ZONE`). A port translation uses a service of the
  policy with exactly that port, or a new one (`tcp-443`). What a rule
  translates to is written as one address or one range (`r-192.0.2.8_30` for
  a network of the source); a pool must be one range. Address for address
  between two ranges is written with the method one-to-one; static NAT for
  both directions as two rules (`NAT_BIDIRECTIONAL`).
* **Sophos to Sophos** is not a copy. System hosts are referred to by name
  (`SYSTEM_HOST`), the policies of a rule by name (`PROFILES_BY_NAME`), host
  names with a wildcard are written back, and the file keeps the API version
  of the source. Users and schedules are not written: such rules are
  disabled, as to every target. Linked NAT rules come out as rules of their
  own, IP lists as host groups.

### Cisco Secure Firewall

A Firewall Threat Defense device is managed by a Management Center (FMC) or by
its own Device Manager (FDM). The two hold the same kind of policy in two
shapes of JSON, and FWShift reads and writes both: `fmc` and `fdm`.

**What is read**

* **Access rules**, first match, top to bottom. A Management Center keeps
  them in a mandatory and a default section, and a policy can inherit from
  another: the mandatory rules of the policy at the top come first, then
  those of its children down to the policy that is read, then the default
  rules back up. A Device Manager has one list. The place of a rule is the
  index the manager gives it, not where it stands in the file.
* **Actions.** *Allow* and *Trust* allow; *Trust* is kept as "no inspection"
  and comes back as *Trust* for another Cisco manager. *Block* drops, *Block
  with reset* resets. *Interactive Block* is converted as a block
  (`INTERACTIVE_BLOCK`). A *Monitor* rule decides nothing and is left out
  (`MONITOR_RULE`). An action FWShift does not know makes the rule
  unsupported, as a rule that blocks.
* **The default action** of the policy is what happens to traffic no rule
  matches: *Block* is the model's deny, anything else (network discovery, an
  intrusion policy) lets the traffic through. Without the policy in the input
  it is taken to block (`DEFAULT_ACTION_UNKNOWN`).
* **The prefilter policy** of a Management Center comes before the access
  rules, and its rules are read as the first rules of the policy. A
  *Fastpath* rule allows without inspection, a *Block* rule drops. An
  *Analyze* rule hands its traffic to the access rules: that is what happens
  to traffic no prefilter rule matches, so the rule itself is not converted.
  But it also keeps the prefilter rules **below** it from deciding that
  traffic, and one list of rules cannot say that. A Fastpath rule below an
  Analyze rule that it overlaps is therefore not converted, since it would
  let through what the access rules were to decide; a Block rule in that
  position is kept and reported, since it blocks more than it did
  (`PREFILTER_ANALYZE`). Whether two rules overlap is told from their zones
  and addresses; ports are not looked at, so that a rule is rather called
  overlapping than not.
* **Tunnel rules** of the prefilter policy match the traffic that carries a
  tunnel. They are converted as rules for that traffic: GRE (protocol 47),
  IP in IP (4), IPv6 in IP (41), Teredo (UDP port 3544), between the tunnel
  endpoints the rule names (`TUNNEL_RULE`); a rule for both directions
  becomes two. What happens to the connections inside the tunnel (a tunnel
  zone, rezoning) is not converted. The default action of the prefilter
  policy for tunnels, when it blocks them, becomes a last prefilter rule
  (`prefilter-default-block-tunnels`).
* **Conditions.** Zones, networks and ports are read. A rule's source ports
  and destination ports must both match, and are read as one service with
  both. Users are read and reported; no target converts them, so the rule is
  disabled. Application, URL, VLAN tag, security group tag, dynamic object
  and identity conditions, time ranges, and any field FWShift does not know
  make the rule unsupported: it is written disabled. A condition that is
  there and cannot be read (not a list, a reference without a name) does the
  same; a condition that holds nothing is no condition, which is how the
  managers write "any".
* **Objects.** Hosts, networks, ranges and FQDN objects, network groups with
  objects and (Management Center) literal addresses; port objects for TCP and
  UDP, ICMP and ICMPv6 objects, other protocols by number or by name, port
  groups; and what a rule spells out itself. An object the rules name and
  the input does not hold in full cannot be converted, and what uses it is
  disabled, with two exceptions that every manager has and nobody can change:
  `any-ipv4` and `any-ipv6` (`PREDEFINED_OBJECT`). Objects of a kind that has
  no addresses to read (countries, dynamic objects) cannot be converted.
  Objects the manager comes with are remembered as such.
* **What a rule does with its traffic.** Intrusion and file policies are
  reported as security profiles, logging at the beginning and the end of a
  connection is read, the category of a rule is kept as a tag.
* **NAT**, in the order the device applies it: manual rules before the
  automatic ones, the automatic ones as the device sorts them (static before
  dynamic, then the fewest addresses first), then the manual rules "after
  auto". The rules are those of an ASA and mean the same: static and dynamic
  translation, PAT pools, the address of an interface, ports of a server
  published on an address, identity rules that exempt traffic. A manual rule
  with a destination is the rule of its connections: no other rule takes
  part in them. A static rule translates in both directions; where it also
  names a destination, only the direction it is written for is converted
  (`NAT_REVERSE_DIRECTION`).
* **Interfaces.** A NAT rule of a Management Center names security zones or
  interface groups, one of a Device Manager names interfaces. The model has
  zones: an interface becomes its zone, an interface group the zones of its
  interfaces (`NAT_INTERFACE` when that is more than the rule named, or when
  the input does not tell). "The address of the interface" is converted with
  the address the interface has in the input (`NAT_INTERFACE_ADDRESS`), which
  needs the interfaces of the device in the input.
* **Access rules name real addresses.** The device translates the
  destination before it asks its access rules. Other platforms ask first:
  for them FWShift adds or replaces the translated address in the rules that
  cover it, as for an ASA (`NAT_DESTINATION_REWRITTEN`, and the other
  findings of that kind under *NAT* above).

**What is written**

* **For a Management Center, a script** (section 10): the objects, a new
  access control policy that blocks by default, with every rule in its
  mandatory section, and a new NAT policy. **For a Device Manager, a file**
  for its configuration import: the objects, the access rules, the NAT rules.
* **Addresses.** A host, a network and a range are objects of three kinds;
  an address a rule or a group spells out gets an object (`h-192.0.2.7`,
  `n-192.0.2.0_24`, `r-...`). Every address of an IP version is the object
  the manager has for it (`any-ipv4`, `any-ipv6`); both together is a rule
  without that condition.
* **Groups.** A network group holds no FQDN objects: the group is written
  without them and the rules that use it name them as well (`GROUP_SPLIT`).
  A group of a Management Center can hold groups; the script creates them
  level by level, because one call cannot name what the same call creates. A
  Device Manager is given the objects themselves.
* **Services.** A port object is one port or one range of TCP or UDP: a
  service with more becomes a port group of such objects under its name
  (`SERVICE_SPLIT`). ICMP and ICMPv6 are objects with a type and a code.
  Another IP protocol is written into the rule as a number for a Management
  Center, and as a protocol object for a Device Manager, which has names for
  most protocols and none for some (IP in IP and IPv6 in IP among them): a
  service with one of those is not converted there. SCTP ports cannot be
  said by either. A port that an object of the source, or of the manager,
  already says is that object: no second one is made.
* **Source ports** are a condition of their own, next to the destination
  ports, and both must hold. A service with source ports for some of its
  entries becomes one rule per set of source ports, each with the
  destination ports that go with it (`RULE_SPLIT`): `name`, `name-2`, ...
* **Negation.** No access rule negates. A negated address list is written
  as the addresses that are left, as ranges for the IP version it names and
  the whole of the other one (`NEGATION_AS_ADDRESSES`). A negated list with a
  host name cannot be turned round: the rule is left out, because written
  without the negation it would say the opposite (`NEGATION`). A negated
  service is not converted.
* **Rules that cannot be converted.** For a Management Center they are
  written in their place, disabled, with a comment that says so
  (`FWSHIFT: disabled by the converter, see the report.`), and the objects
  they need are placeholders: a host object for an address nothing has
  (192.0.0.8), a port object for TCP port 1, each with `FWSHIFT PLACEHOLDER`
  in its description. **A Device Manager has no rule that is switched off.**
  A rule that is disabled on the source (`DISABLED_RULE`) or cannot be
  converted is left out of the file, and the report lists it as skipped.
  Read the report with that in mind: a blocking rule that is left out is not
  there to be finished by hand.
* **Actions and logging.** Allow, Trust (for a rule that was a Trust or a
  Fastpath rule on a Cisco source), Block, Block with reset. A Device Manager
  has no reset (`RESET_ACTION`). A rule that blocks logs at the beginning of
  a connection, since a blocked connection has no end; a Device Manager logs
  at the end, at both ends or not at all. The description of a rule becomes
  its comment on a Management Center; a rule of a Device Manager has none.
* **Zones.** Rules name security zones. For a Management Center the script
  uses those that exist and creates those that do not, empty. A file for a
  Device Manager does not hold zones, because an import would replace a zone
  of the same name and take its interfaces out of it: they must exist
  (`ZONES_REQUIRED`).
* **Names.** Letters, digits, `.`, `_` and `-`, up to 64 characters for an
  object; a rule name may hold spaces on a Management Center (50 characters;
  128 without spaces on a Device Manager). Names that differ in case only
  are kept apart with a suffix. An object named like one the managers come
  with (`any`, `any-ipv4`, `HTTP`, `HTTPS`, `SSH`, ...) is renamed.
  `--target-prefix` puts a prefix in front of every object that is created.
  From a manager to a manager of the same kind the names of the source are
  kept as they are, whatever is in them; the names FWShift adds (`h-...`,
  `tcp-...`) follow the rule above, and two names that differ in case only
  are still kept apart.
* **NAT rules** are written as manual rules, before the automatic ones, in
  their order: the place where a first-match list of another platform fits.
  Automatic rules of a Cisco source become manual rules in the place the
  device gave them. A service of several ports becomes a rule per port (16
  at most). A translation to several addresses with port translation is a
  PAT pool, which holds hosts and ranges: a network of the source is written
  as the range it is. A destination translation is written the way the
  device writes one: a static rule that leaves the source alone, works in
  one direction and names the interface the traffic comes in on. For a Cisco
  source a published port comes back as the device had it, from the side of
  the server, and "the interface" as that word.
* **Interfaces of a NAT rule.** A Management Center takes zones. A Device
  Manager takes interfaces, by their logical name: give them with
  `--interface-map` (for each interface of a zone; for a source whose zones
  are interfaces, the zone name itself). Without them a rule is written for
  any interface (`NAT_ZONES`), and one that needs the address of an interface
  is not converted. The file names every interface as a physical interface;
  a subinterface or an EtherChannel needs its type changed by hand
  (`INTERFACES_REQUIRED`).
* **Cisco to Cisco** is not a copy. Objects the manager comes with are named
  and not created (`EXISTING_OBJECT`); the script checks that they are
  there. Intrusion and file policies, users, time ranges and the application
  and URL conditions are not written: the first are reported, a rule with
  one of the others is not converted, as to every target. Prefilter rules
  are written as access rules: a Fastpath rule as a Trust rule in the same
  place (`PREFILTER_AS_TRUST`). The inheritance of a policy is flattened into
  the one policy that is written.

### pfSense

pfSense turns its configuration into rules for pf, the packet filter of
FreeBSD, each time it loads the filter. What a rule of the configuration
means is what pf makes of the lines pfSense writes for it: FWShift follows the
code that writes them (`filter.inc` of pfSense 2.6, 2.7.2 and the current
development branch) and not the web pages, which say less.

**What is read**

* **Zones** are the enabled interfaces, by their descriptions (`WAN`, `LAN`,
  `DMZ`). A rule of an interface group is a rule of each of its interfaces,
  in the place pfSense gives group rules. The groups pfSense makes itself are
  zones when they are in use: `OpenVPN`, `IPsec` (enc0), `L2TP`, `PPPoE`.
* **Order.** pfSense evaluates the quick floating rules first, then the rules
  of interface groups, then those of the interface; where two groups share an
  interface, versions after 2.7.2 take them group by group, earlier ones in
  the order of the file (`RULE_ORDER_VERSION`). Floating rules that are not
  *quick* decide where nothing else did, the last one first: they go to the
  end (`FLOATING_LAST_MATCH`). An interface rule decides on arrival; a
  floating rule for traffic that **leaves** by an interface decides after
  that, and blocks what an arrival rule passed: such a rule becomes a rule
  from every zone to that zone, ahead of the others. A floating rule that
  passes what leaves decides nothing for forwarded traffic and is left out
  (`FLOATING_OUT_PASS`); one that passes what leaves before one that blocks
  it cannot be said in the model, and is unsupported.
* **Addresses.** Aliases of hosts and networks become groups, nested as they
  are; host names in them become FQDN objects. A rule for one IP version
  takes the addresses of that version (`Servers IPv4`). The network and the
  address of an interface (`LAN net`, `WAN address`) include its virtual IPs,
  as pfSense does; *This Firewall* is every address of the firewall that the
  configuration holds, which is less than pf's `(self)` on a firewall with
  addresses from DHCP or tunnels. Addresses that are not in the configuration
  are asked for with `--interface-address` (section 3). URL table aliases are
  files on the firewall: rules that name one are disabled.
* **Services.** A rule names one protocol (`tcp/udp` is two) and ports, or a
  port alias. A port named as a service (`ssh`, `https`) is read as its number;
  a protocol and no port is every port; a port and no protocol is TCP, as
  pfSense writes it. ICMP types are read by name.
* **IP versions.** A rule for IPv4 and IPv6 is read once, or as two rules where
  the halves differ (an interface without IPv6 network, an alias of one
  version). Without *Allow IPv6*, IPv6 is not read (`IPV6_NOT_ALLOWED`).
* **Rules pfSense adds itself.** *Block private networks and loopback
  addresses* on an interface becomes a rule at the top of that interface
  (`AUTOMATIC_RULE`). The other rules pfSense puts before the configuration
  are not converted (`PFSENSE_AUTOMATIC_RULES`), and neither is *Block bogon
  networks* (`BOGONS_NOT_CONVERTED`).
* **NAT.** pfSense looks its rules up after a port forward: a rule of the
  configuration names the translated address. In the model a rule names the
  address as it arrives, so the rules are rewritten for the port forwards, as
  for the other platforms that look up after NAT (`NAT_DESTINATION_REWRITTEN`).
  Port forwards are read with their NAT reflection (`NAT_REFLECTION`): in
  *pure NAT* mode the forward also applies to what arrives on the inside
  interfaces; in proxy mode that is not converted (`NAT_REFLECTION_PROXY`). A
  port forward whose filter rule association is *Pass* passes by itself, and
  gets a rule of its own (`AUTOMATIC_RULE`); a linked rule is a rule of the
  interface like any other. A 1:1 rule becomes two rules, one for each
  direction. Outbound NAT is read in its four modes: *automatic* as the
  rules pfSense makes for every interface with a gateway (from the networks
  of the other interfaces, of static routes over them and of OpenVPN and
  IPsec mobile clients), *hybrid* as the manual rules and then those, *manual*
  as the manual rules, *disabled* as none; *Do not NAT* is a no-NAT rule. Of
  port forwards that map a range of ports to another range, only one port to
  one port or a range to the same range is converted (`NAT_NOT_CONVERTED`).
  IPv6 NAT and NPt are not converted (`NPT_NOT_CONVERTED`).
* **What is not converted.** Schedules (the rule keeps the schedule, which
  every target reports), gateways on rules (`POLICY_ROUTING`), tags and
  other match conditions beyond addresses, ports, protocol and ICMP type
  (`UNSUPPORTED_MATCH`, the rule is disabled), limiters, queues and state
  options (reported on the rule), rules without state (`STATELESS_RULE`),
  *match* rules (`MATCH_RULE_SKIPPED`), bridges (`BRIDGE_NOT_CONVERTED`) and
  the captive portal (`CAPTIVE_PORTAL`). Rules pfSense itself would not load
  are not converted (`RULE_NOT_LOADED`).

**What is written**

* **One file** with the areas Aliases, NAT and Firewall Rules, written for
  pfSense 2.7 and later, to be restored area by area (section 10).
* **Interfaces.** A zone that is named like an interface of pfSense (`wan`,
  `lan`, `opt1`), or is mapped to one with `--zone-map`, or whose interfaces
  are mapped to them with `--interface-map`, becomes that interface. Any
  other zone keeps its name, which pfSense takes when an interface group of
  that name exists (`INTERFACES_REQUIRED`); a name that cannot be an
  interface group disables its rules (`INTERFACE_NAME`). From a pfSense
  source the interfaces stay as they were; a rule of an interface group comes
  back as a rule of each of its interfaces.
* **Rules** are written on the interface traffic arrives on, one per source
  zone. A rule of pfSense cannot name the interface traffic leaves by: as for
  an ASA, give the networks behind every zone with `--zone-network`, and a
  rule for one destination zone is kept to it; without them such a rule is
  disabled, or applies wherever its named destination is reached
  (`EGRESS_INTERFACE`). A deny for every source zone to some zones that
  stands above every rule that passes is written as a floating rule for
  traffic that leaves by those interfaces (see `FLOATING_AFTER_NAT` for when
  that cannot name a source).
* **The firewall itself.** The rules of an interface also decide what goes to
  the firewall. A rule of another platform that passes traffic to any
  destination is written for any destination except *This Firewall*, so that
  it does not open the firewall's own services (`SELF_EXCLUDED`).
* **Services.** A rule names one protocol: a rule with several becomes one
  rule per protocol (`RULE_SPLIT`), TCP and UDP with the same ports one rule
  for `tcp/udp`. Several ports are a port alias, whose name has an upper-case
  letter or an underscore so that pfSense does not take it for a service
  name. ICMP types are written by name; ICMP codes (`ICMP_CODE`) and protocols
  pfSense has no name for (`PROTOCOL_NOT_AVAILABLE`) disable the rule.
* **Addresses.** Objects and groups become aliases (up to 31 letters, digits
  and underscores; `RENAMED` where that changes a name). A list of addresses in
  a rule becomes an alias of its own (`src_<rule>`, `dst_<rule>`). Words of
  pfSense from a pfSense source (`LAN net`, *This Firewall*) are written as
  those words again.
* **NAT.** The rules are written for the translated destination, as pfSense
  looks them up. A destination translation becomes a port forward on each
  interface its traffic arrives on, without NAT reflection and without a
  linked rule (the rules are in the file). Bi-directional static NAT of
  equal size becomes a 1:1 rule; source NAT becomes outbound NAT in manual
  mode, *Do not NAT* for exemptions. When only destinations are translated,
  outbound NAT is switched off, as on the source; a policy without NAT gives
  no NAT area, and the firewall keeps its own. pfSense reads `opt` in the
  source of an outbound NAT rule as an interface name, so an alias with
  `opt` in its name is wrapped in another alias there.
* **Defaults.** pfSense blocks what no rule passes. A source that allows it
  gets a rule that passes everything at the end of every interface
  (`INTERZONE_DEFAULT`).

### SonicWall

**What is read**

* **Access rules** are kept per pair of zones (from, to), and are first match
  within their pair. Each row of the export is a rule; where every row says
  its priority, the rules of a pair are in that order, otherwise in the order
  of the file. A rule names one source, one destination and one service, each
  an object, a group or nothing, which is "any". Allow allows; Deny and
  Discard both block (`0` and `1`: the published readers of the format do not
  agree which is which, and the model has no need to know). IPv4 and IPv6
  rules are tables of their own.
* **Default rules.** What no rule of a pair matches, the default rule of that
  pair decides. An export holds it as a row (the rule for any source, any
  destination and any service at the end of the pair). Where a pair has none,
  FWShift adds what SonicOS does by default for the security types of the two
  zones: it allows from a trusted or wireless zone to a public or untrusted
  one, and from a public zone to an untrusted one (`DEFAULT_RULE_ASSUMED`);
  it denies the rest, and says so for types whose default is not documented
  (`DEFAULT_RULES_UNKNOWN`). Traffic between interfaces of one zone passes
  where the zone has *Allow Interface Trust*.
* **NAT.** An access rule names the destination as it arrives and the zone the
  translated traffic goes to, as the model does: nothing is rewritten. NAT
  policies are one table, first match. A policy translates the source, the
  destination and the service at once, and matches the interface traffic
  arrives on and the one it leaves by: an interface becomes its zone
  (`NAT_INTERFACE` when the zone has other interfaces too). Source NAT to the
  address of the interface traffic leaves by (`X1 IP`) is translation to the
  interface; to an object of the size of the original source, address for
  address; to anything else, translation with ports. A reflexive policy gets
  its mirror image as a rule of its own (`NAT_REFLEXIVE`).
* **Objects.** Hosts, ranges, networks and FQDN objects; groups, nested. The
  zone of an object is not read: SonicOS does not match by it. Objects
  SonicOS has by itself are worked out from the interfaces (`DEFAULT_OBJECT`):
  `Xn IP`, `Xn Subnet`, `Xn Default Gateway`, `All Xn Management IP`, `<zone>
  Subnets`, `Firewalled Subnets` (the networks of every interface that is not
  in an untrusted zone), `All Interface IP`, `All WAN IP`, `WAN Primary IP`
  (taken to be X1). Services: TCP and UDP port ranges and IP protocols; ICMP
  service objects are not read, because how an export stores type and code is
  not known; the default services of SonicOS (`HTTP`, `HTTPS`, `SSH`, `Ping`,
  ...) where a rule names one the export does not list.
* **Not converted:** users (`USER_MATCH` on every target), schedules, a
  source port service, Geo-IP and botnet filtering of a rule (reported as
  profiles), bandwidth management and the other settings of a rule, IPv6 and
  MAC address objects (`OBJECTS_NOT_READ`), VPN policies, and firewalls in
  Policy mode.

**What is written**

* **Commands** of the SonicOS 7 command line, which enter the configuration
  mode, create objects, NAT policies and access rules, and end with
  `commit`.
* **Rules.** One per pair of zones and IP version, each with its place in the
  pair (`priority manual N`): without it SonicOS would order the rules by
  itself, most specific first. A list of addresses or services becomes a
  group (`src <rule>`, `dst <rule>`, `svc <rule>`); a negated list, the
  addresses that are left (`NEGATION_EXPANDED`). A rule with zone "any"
  becomes a rule for every pair of zones of the policy. Every pair ends in a
  rule that denies, where the model denies what no rule matches
  (`DEFAULT_DENY_ADDED`): SonicOS allows LAN to WAN by itself.
* **Objects** are per IP version, of up to 32 characters, and need a zone: the
  zone the networks given with `--zone-network` put them in, otherwise the
  zone of the first rule that names them. Names SonicOS has itself (`X1 IP`,
  `HTTPS`, `Ping`) are not taken (`RENAMED`), except from a SonicWall, whose
  objects of that kind are used as they are.
* **Services:** TCP and UDP, an object per protocol and range, a group for
  more; ICMP echo request as the default service `Ping` (`ICMP_AS_DEFAULT`).
  Other ICMP and other IP protocols are not written: the command for them was
  not found in what SonicWall publishes, and the rules that need them are
  disabled.
* **NAT policies** name interfaces: those of the zones, mapped with
  `--interface-map` (`X1`), one policy per pair of interfaces. Source NAT to
  the address of the outgoing interface is translation to `Xn IP`.
  Bi-directional static NAT is two policies.

### WatchGuard

**What is read**

* **Policies** are first match, in the order of the file (`abs-policy-list`).
  Allow and the proxy policies allow; Deny blocks. A policy that does not say
  whether it is enabled, or whose rule in `policy-list` says otherwise than
  the policy, is disabled. In automatic order the Firebox orders policies
  itself (`POLICY_ORDER_AUTOMATIC`, section 3).
* **Interfaces are the zones.** A policy names no zones: its From and To
  lists hold aliases, and an alias holds members that are an address *at* an
  interface (`Any-Trusted`, `External`, a named interface), or other aliases.
  `Any-Trusted`, `Any-External` and `Any-Optional` become the interfaces of
  that type (when an interface does not say its type, a member of these is
  not read); `Any` and `Firebox` as an interface are every zone. A policy
  whose lists hold members of several interfaces becomes one rule per pair of
  From and To members, which together match what the policy matched
  (`POLICY_SPLIT`). A member that names a VPN (`Any-BOVPN`, `Any-MUVPN`,
  `SSL-VPN`) is not read, and its policy is disabled.
* **Users.** A user in the From list is a user match (`USER_MATCH` on every
  target); a user in the To list is not read, and its policy is disabled.
* **Static NAT.** A static NAT action in the To list of a policy is read as
  the model has it: the rule names the public address, to any zone, and a NAT
  rule translates it to the server, for the sources and the service of that
  policy (one NAT rule per policy and per interface of its sources). Network
  dynamic NAT and 1-to-1 NAT are not read (`NAT_NOT_READ`).
* **Objects.** Address groups of hosts, networks, ranges and host names;
  `Firebox`, the addresses of the interfaces of the configuration. Services:
  TCP and UDP ports and ranges, ICMP and ICMPv6 type and code (255 is any),
  other IP protocols; protocol 0 is any.
* **Default.** The Firebox denies what no policy allows.
* **Not converted:** proxy actions (reported as profiles, approximated),
  schedules, policy-based routing, the NAT settings of a policy,
  application control, intrusion prevention and the other subscription
  services of a policy, and everything outside the policy.

**What is written**

* **The policy part of a configuration file** of Policy Manager: address
  groups, services, static NAT actions, aliases and policies, and the setting
  for manual policy order. Not interfaces, not system settings (section 10).
* **Policies** in the order of the model, manual order: the first that
  matches decides, and the Firebox denies the rest (`INTERZONE_DEFAULT` when
  the source allowed it). Each rule becomes one policy with an alias
  `<rule>.1.from` and `<rule>.1.to` that holds every pair of zone and address
  the rule names; zone "any" is the interface `Any`. The zones must be
  interfaces of the Firebox under those names (`INTERFACES_REQUIRED`; rename
  them with `--zone-map`); a zone named like an interface class of Fireware
  (`Any-Trusted`, `Firebox`) is refused. A rule written disabled has
  `FWSHIFT inactive, see the report` in its description.
* **No negation:** a negated list is written as the addresses that are left
  (`NEGATION_EXPANDED`).
* **Objects** are address groups (a placeholder that matches nothing,
  `192.0.0.8`, for one that cannot be written), groups of the model are
  aliases. Services: TCP and UDP ports and ranges, ICMP and ICMPv6, IP
  protocols. Source ports, SCTP ports, port 0 alone and protocol 0 alone
  cannot be named, and the rules that use them are disabled.
* **Static NAT.** A NAT rule that translates the destination to one IPv4
  address, from one public IPv4 address or range, becomes a static NAT
  action. It goes into the To list of the policy that allows exactly its
  traffic: the same destination, the same service and zones, sources within
  those of the NAT rule, and no other NAT rule before it. A rule that allows
  the public address otherwise names it untranslated (`NAT_NOT_IN_POLICY`).
  The action has no interface to the server, so a rule for one destination
  zone then allows the translated traffic in any (`NAT_ZONE_DROPPED`). An
  action no policy uses is still written (`NAT_NO_POLICY`). Source NAT is
  dynamic NAT on a Firebox and is not written (`NAT_NOT_CONVERTED`).

### Barracuda

**What is read**

* **Forwarding rules**, first match, in the order of the answer. A rule names
  one IP version (`ipVersion`), a source, a destination and a service, each a
  reference to an object or `Any`. Pass allows; Block drops; Deny answers with
  a reset or an ICMP message. A rule that does not say whether it is
  deactivated, or holds a key the parser does not know, is not used.
  Bi-directional rules become two rules (`BIDIRECTIONAL_SPLIT`). What no rule
  matches is blocked.
* **Interfaces as zones.** A rule has no zones: the firewall picks the way out
  by its routes. An entry of a network object can name the interface traffic
  arrives by, which counts where the object is the source of a rule: such a
  rule becomes one rule per interface, the interfaces as zones
  (`INTERFACE_SPLIT`). In a destination the interface of an entry does not
  count. A bi-directional rule whose objects name interfaces is not used.
* **Network objects:** addresses, networks, ranges and host names, references
  to other objects, nested; excluded entries are subtracted. Where a rule of
  one IP version names an object that holds both, or names interfaces, a
  group of what the rule uses is made once (`Office-LAN (IPv4)`, `Admins
  (port2)`). Geolocation, wildcard, external and dynamic objects, and entries
  with a MAC address, are not read.
* **Service objects:** TCP and UDP ports and client (source) ports, ICMP and
  ICMPv6 (every type: a service entry of the firewall names none), other IP
  protocols; references to other service objects. The limits of ICMP echo
  requests are not converted (`ICMP_LIMITS`).
* **Not converted:** the actions Dst NAT, Map, App Redirect and
  Broad-Multicast (the rule is not used), Cascade and Cascade Back (read as a
  rule that blocks and is not used: the rules of the list it hands traffic to
  are not read), connection objects (`CONNECTION_NOT_READ`), schedules and
  users (on every target), application control, URL filter and IPS (reported
  as profiles), the mismatch policy of a rule, the host firewall, and a
  Control Center.

**What is written**

* **A shell script** of curl calls to the REST API (section 10): network
  objects, service objects, then every rule, deactivated, at the top of the
  list, last rule first, so that they end up in the order of the model above
  the rules the firewall has; then the rules that are to be active are
  activated, first rule first.
* **Rules** of one IP version each (`IP_VERSION_SPLIT`), each side one
  object: the object of the model where the rule names just that one, else an
  object of the rule (`<rule>.src`, `<rule>.dst`, `<rule>.svc`). Ranges become
  the networks that make them up; a negated list, the addresses that are left
  (`NEGATION_EXPANDED`). A rule written deactivated has `FWSHIFT inactive, see
  the report` in its comment.
* **Zones.** A zone of the source is written as the interface of the entries
  of the source object, where the interface is known (`--interface-map`, or a
  CloudGen source), otherwise as the networks behind it (`--zone-network`); a
  zone of the destination as its networks (`ZONE_BY_NETWORKS`), except where
  the source worked the zones out from the routes itself. Where neither is
  given, a rule that allows is deactivated (`ZONE_NETWORK_MISSING`) and a rule
  that blocks blocks in every zone (`ZONE_WIDENED`).
* **What no rule matches.** The model blocks it; the firewall blocks it only
  at the end of its own list. The rules FWSHIFT-BLOCK and FWSHIFT-BLOCK-v6
  follow the converted rules and block everything, deactivated
  (`BLOCK_RULE_INACTIVE`): activate them once the rules below them (management
  access, default rules) have been looked at.
* **Services:** TCP and UDP ports with client ports, ICMP and ICMPv6 of every
  type, other IP protocols. A service with an ICMP type or code cannot be
  written, and the rules that use it are deactivated. ICMP goes only into the
  rule of its IP version.
* **Names** are kept to 32 letters, digits, periods, underscores and hyphens,
  and told apart without regard to case (`RENAMED`). Host names are written as
  placeholders that match nothing, since how the API spells a hostname object
  is not known.
* **NAT** is not written (`NAT_NOT_CONVERTED`): set Dst NAT, Map or the
  connection object on the rule by hand.

### Juniper SRX

**What is read**

* **Security policies** per pair of zones (`from-zone ... to-zone ...`, a
  zone with itself too), first match; then the global policies, first match,
  with `match from-zone` and `to-zone` where they have them; then the default
  policy (`deny-all` unless `default-policy permit-all`). Permit allows, deny
  drops, reject answers. A policy without an action, an address or an
  application is not used.
* **NAT before the policy.** An SRX applies static and destination NAT before
  it looks the policy up: a policy names the translated destination and the
  zone it is routed to. The model has the original destination, and the
  parser adds it (`NAT_DESTINATION_REWRITTEN`, `NAT_PORT_TRANSLATION`).
* **Address books.** A name is looked up in the book of the zone (a book
  attached to it, or the address book of the zone itself), then in the global
  one; global policies and NAT use the global book. Objects of a zone's book
  keep their book in their name (`web (dmz-book)`, `web (zone dmz)`); an
  object whose name looks like an address is renamed (`10.1.1.1 (object)`).
  Addresses, prefixes, ranges, DNS names; wildcard addresses are not read.
* **Negation:** `source-address-excluded` and `destination-address-excluded`.
* **Applications:** protocol, destination and source port (by number, range
  or name), ICMP and ICMPv6 type and code (by number or name), terms;
  application sets, nested; the predefined applications of FWShift's table
  (`PREDEFINED_APPLICATIONS`). An application with a protocol that has ports
  and no destination port, or with an RPC program or UUID, is not used.
* **Deactivated** statements are not there: a policy, an address in a policy,
  a NAT rule.
* **NAT:** static NAT (as a destination NAT from the zones of its rule set and
  a static source NAT the other way), destination NAT with pools (one
  address, or a range picked from per connection, and a port), source NAT to
  the interface or to a pool (with or without port translation), `off`. Rule
  sets of an interface before those of a zone. Rule sets of a routing
  instance are not read.
* **Not converted:** schedulers, `source-identity` (a user match),
  `dynamic-application` (unified policies), `url-category`, application
  services (reported as profiles), policy-based VPN (`permit tunnel`), the
  zone `junos-host`, logical systems and tenants, screens and
  `host-inbound-traffic`.

**What is written**

* **Set commands** for `load set`: applications, the global address book,
  security policies, NAT, in the order the SRX needs them.
* **Policies.** A rule of the model for given zones becomes a policy in each
  pair of zones it covers (`RULE_SPLIT`), in the order of the model; zone
  "any" stands for every zone the policy knows (`ZONES_EXPANDED`). Rules at
  the end of the model become global policies where that takes fewer
  policies: the SRX looks at them after the pairs of zones anyway, so only
  rules at the end can go there. Policies name the destination after NAT.
* **Negation** is written as `...-excluded` for up to 10 IPv4 addresses;
  otherwise as the addresses that are left (`NEGATION_EXPANDED`).
* **Disabled rules** are written and then deactivated (`deactivate security
  policies ...`), with `FWSHIFT inactive, see the report` in their
  description; placeholders that match nothing (`192.0.0.8/32`) carry
  `FWSHIFT PLACEHOLDER`.
* **Applications:** one term per protocol and port range, source ports, ICMP
  and ICMPv6 type and code, IP protocols; groups as application sets.
* **NAT:** destination NAT with a pool per rule, in a rule set per zone the
  traffic comes from; a destination NAT with the source NAT that undoes it,
  and a bi-directional static NAT, as static NAT (`NAT_STATIC`,
  `NAT_BIDIRECTIONAL`); source NAT to the interface or to a pool, in a rule
  set per pair of zones; a rule without translation as `source-nat off`. A
  NAT rule of Junos matches one destination prefix and one port range.
* **Names** of up to 63 characters; objects that start like a name Junos keeps
  for itself (`junos-`, `static_nat_`) are renamed; a zone name the SRX cannot
  take is refused (use `--zone-map`). If the source allows what no rule
  matches, `default-policy permit-all` is written (`DEFAULT_PERMIT`).

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

### Sophos Firewall

The output is an `Entities.xml`, or, with `-o NAME.tar`, the archive that
holds it.

1. Make sure the zones named in `ZONES_REQUIRED` exist, and convert with
   `--interface-map` so that the NAT rules name the ports of the target.
2. Convert with `-o import.tar`. (Or put the XML in a tar archive yourself;
   the file in it must be called `Entities.xml`.)
3. On a firewall that is not in production: *Backup & firmware > Import
   export*, import the archive.
4. **Check what arrived.** An import can stop at the first entity the firewall
   does not take, and FWShift has not seen what the web console says then.
   Compare the number of hosts, services, firewall rules and NAT rules with
   the summary of the report. Because every rule stands after the one before
   it, a rule that is not taken keeps the rules after it out as well.
5. An import **overwrites** what the firewall has under the same name. FWShift
   avoids the names of the services a firewall comes with; for everything
   else that might exist already, convert with `--target-prefix`.
6. The rules land below the rules the firewall has, IPv4 and IPv6 each in
   their own rulebase, and the NAT rules below its NAT rules. A rule that is
   there already and stands above them decides, or translates, first: a new
   firewall has a default source NAT rule.
7. The first line of the file names API version 1800.1 (SFOS 18.0). A
   firewall imports a file of its own version or an older one. Sophos to
   Sophos, the file keeps the version it was read with.
8. FQDN hosts need name resolution on the firewall.

### Cisco Secure Firewall Management Center

> **The script has never talked to a Management Center.** It was written
> from Cisco's REST API documentation and run against a stand-in that the
> tests bring along. What it counts on is listed in `DEVELOPMENT.md` (*Vendor
> behaviour the code relies on*); the first run belongs on a Management
> Center where a mistake costs nothing.

The output is a Python script. It holds a small program and, after it, the
policy as data; it needs Python 3.8 or newer and nothing else, on any machine
that reaches the Management Center. It talks to the REST API, which must be
enabled, as a user that may create objects and policies. Use a user of its
own: according to the API guide, one that is logged in to the web interface
at the same time is logged out there.

```sh
python3 load_policy.py --show
python3 load_policy.py --host fmc.example.net --user api-user --dry-run
python3 load_policy.py --host fmc.example.net --user api-user
```

1. `--show` says what the script would create, without connecting: the
   policies, how many objects of each kind, the zones, and the objects it
   counts on. `--plan` prints the policy it carries, as JSON.
2. `--dry-run` logs in, reads what the Management Center has and checks every
   name. Nothing is created.
3. A run without either does the same checks and then creates, in this
   order: the security zones the rules name and that are missing; the
   network objects, the port objects and the groups; a new access control
   policy with the rules; a new NAT policy with the NAT rules, when there are
   any. It stops at the first thing the Management Center refuses. After the
   rules it asks for them again and compares: as many as were sent, in the
   order they were sent. If not, it says so and stops; the policy is then not
   the policy that was converted.

The password is taken from the environment variable `FMC_PASSWORD`, or asked
for when the script runs in a terminal; without either it stops. The certificate of the Management Center is checked: give the
certificate of the authority that signed it with `--cafile`. `--insecure`
switches the check off and belongs in a lab. The password and the token go to
the host that was named and nowhere else: a redirect is not followed, and
plain `http` is spoken only to the machine the script runs on.

What the script will not do:

* **Change anything that exists.** If an object it would create exists under
  the same name (whatever its case), it lists the names and stops before it
  creates anything: convert again with `--target-prefix`. The same when an
  access control policy or NAT policy of its name exists: give another with
  `--name`, or with `--target-policy` when converting. A security zone that
  exists is used as it is, also when it is written there in another case; a
  zone name that an interface group has stops the run, before anything is
  created.
* **Create an object the policy only counts on.** A policy that was read from
  a Management Center names the objects it comes with (`any-ipv4`, `HTTPS`);
  if one is missing on the target, the script says which and stops.
* **Assign or deploy.** The policies are assigned to no device. Nothing
  reaches a firewall until someone assigns them and deploys.

What else to know:

* The new access control policy **blocks by default**, has every rule in its
  mandatory section, and uses the default prefilter policy and no intrusion,
  file or SSL policy. Attach the inspection the report lists
  (`PROFILES_NOT_CONVERTED`).
* A **zone the script creates is empty** and matches no traffic. Put the
  interfaces of the devices in it. A rule for such a zone does nothing until
  then, which for a rule that blocks is worth knowing.
* What is created is written to a **journal**, call by call
  (`fwshift-fmc-NAME.journal.json`, or `--journal`; it is there before the
  first object is). `--undo` reads the journal and deletes it all again, the
  policies first, on the Management Center and in the domain the journal
  names. It deletes by id: **an object you changed since is deleted too**,
  and so is a rule you added to the new policy. What something else uses by
  then is refused by the Management Center, stays, and is listed; what is
  gone already is said to be gone. After a run that stopped half way: undo
  it, correct the cause, run again.
* When a call is answered with an error, or with something that cannot be
  read, the script asks the Management Center what is there. An object is
  taken as created by the run, and written to the journal, only if it was not
  there before and says what was sent. An object under one of its names that
  says something else is someone else's: the run stops and leaves it alone.
* `--domain NAME` names the domain to work in, for a user that has several.
* The Management Center limits how often it is asked. The script waits when
  it is told to, and logs in again when its token runs out.
* Rules the converter disabled carry the comment
  `FWSHIFT: disabled by the converter, see the report.`

### Cisco Secure Firewall Device Manager

> **The file has never been imported on a device.** Its format follows the
> import and export chapter of Cisco's API guide. Where the steps below say
> what the device does, that is what the guide says, or, where marked, what
> FWShift assumes; `DEVELOPMENT.md` has the list.

The output is a text file for the configuration import of the device: a JSON
list whose first object says what the file is for, and then an object, an
access rule or a NAT rule per line.

1. **The first line.** The guide wants the hardware model and the software
   version of the target in the first object of a file (it says so for a full
   import; FWShift assumes it for a file that adds as well). Converting from an
   export of a Device Manager, FWShift copies both from it. Otherwise the
   file says `REPLACE WITH THE VALUE FROM AN EXPORT OF THE TARGET` in both
   places: export the configuration of the target (section 3), and copy
   `hardwareModel` and `softwareVersion` from its first object.
2. Make sure the zones named in `ZONES_REQUIRED` exist on the device and hold
   their interfaces, and convert with `--interface-map` so that the NAT rules
   name its interfaces (`inside`, `outside`: the logical names). The file
   names every interface as a physical interface; for a subinterface, an
   EtherChannel or a VLAN interface change `"type": "physicalinterface"` in
   that rule to the type an export of the device shows for it.
3. Import it, through the REST API of the device (version 6.5 and later; the
   web interface of newer versions has an upload for it as well):

   ```sh
   call -X POST $ftd/api/fdm/latest/action/uploadconfigfile -F 'fileToUpload=@import.txt'
   call -X POST $ftd/api/fdm/latest/action/configimport -H 'Content-Type: application/json' \
        -d '{"type": "scheduleconfigimport", "diskFileName": "NAME-THE-UPLOAD-ANSWERED", "autoDeploy": false}'
   call $ftd/api/fdm/latest/jobs/configimportstatus
   ```

   (`call` as in section 3.) With `autoDeploy` false nothing is in force
   after the import: the changes are pending. A device that has pending
   changes of its own refuses an import unless the request says
   `"allowPendingChange": true`; deploy or discard them first.
4. **Look at the pending changes** in the web interface before deploying, and
   compare the number of objects and rules with the summary of the report.
5. An import **changes what the device has under the same name**: an object
   or a rule of the file replaces it. FWShift avoids the names of the objects
   a device comes with; for everything else that might exist already, convert
   with `--target-prefix`.
6. The access rules land **below the rules the device has** (a rule without
   an index is added at the end, says the guide), and its default action
   stays what it is. A rule that is there already decides first. The NAT
   rules are manual rules before the automatic ones; FWShift assumes they land
   below the manual rules the device has, and that the container for them is
   called `NGFW-Before-Auto-NAT-Policy`, as in the guide's examples. If an
   export of your device shows another name for it, change `parentName` in
   the file.
7. **What is not in the file:** rules that are disabled on the source, and
   rules that could not be converted. A Device Manager has no rule that is
   switched off, so there is nothing to write them as; the report lists each
   as skipped, with the reason. Go through them before deploying: the rules
   below a blocking rule that is missing allow more than they did.
8. FQDN objects need a DNS group on the device.

### pfSense

> **The file has never been restored on a pfSense.** Its format and what a
> restore does with it are taken from the source code of pfSense
> (`diag_backup.php`, `backup.inc`, `restore_config_section()`).

The output is a pfSense configuration file that holds three areas:
`<aliases>`, `<nat>` and `<filter>` (an area is left out when it would be
empty). It is restored with the restore of one area at a time, which
**replaces** that area: what the firewall has there now is gone.

1. **Back up the firewall** under *Diagnostics > Backup & Restore*. That is
   the way back.
2. **Interfaces and groups.** Assign the interfaces the rules name (`lan`,
   `opt1`, ...: the internal names, which *Interfaces > Assignments* shows as
   `LAN`, `OPT1`), and create the interface groups listed in
   `INTERFACES_REQUIRED` under *Interfaces > Interface Groups*. A rule for an
   interface the firewall does not have is not loaded, without an error.
3. **Addresses of port forwards and 1:1 rules.** The outside addresses they
   use must be addresses of the firewall: the address of the interface or a
   virtual IP (*Firewall > Virtual IPs*, an IP alias or Proxy ARP address).
   Virtual IPs are not in the file.
4. **Restore, area by area:** under *Restore Backup*, choose *Restore area*
   **Aliases**, pick the file, *Restore Configuration*. Then **NAT**, then
   **Firewall Rules**, the same file each time. After each restore pfSense
   reloads its rules by itself. Between two restores the firewall runs with
   the new part and the old rest, so restore in a maintenance window, and
   from an interface that pfSense's own anti-lockout rule keeps open (LAN,
   unless that rule is switched off under *System > Advanced*).
5. **What a restore takes along.** Restoring *Firewall Rules* replaces every
   rule, the separators between them and the setting *Bypass firewall rules
   for traffic on the same interface*; restoring *NAT* replaces every port
   forward, 1:1 rule and outbound NAT rule, and the outbound NAT mode, and the
   rules pfSense had linked to port forwards lose their link. Interface
   settings (*Block private networks*, *Block bogon networks*), schedules,
   gateways and virtual IPs stay as they are. A file without a NAT area
   leaves the NAT of the firewall as it is: do not restore that area then (an
   area that is not in the file is refused).
6. **pfSense checks nothing** it restores: no version, no reference. The file
   is written for pfSense 2.7 and later (CE and Plus); the outbound NAT of 2.6
   has another form. A rule that names an alias or interface the firewall
   does not have is simply not loaded: look under *Status > System Logs >
   System* for errors of the filter reload, and compare the rules with the
   summary of the report.
7. Rules that could not be converted are in the file, **disabled**, with
   `FWSHIFT` in their description; aliases that stand in for an object that
   could not be converted match nothing (`192.0.0.8`, a reserved address).

### SonicWall

> **The commands have never been run on a SonicWall.** Their form follows
> SonicWall's knowledge base; the parts the report lists under
> `SONICWALL_LOAD` (`priority manual`, the name and comment of a NAT policy,
> IPv6 and FQDN objects) are assumed.

1. Make sure the zones listed in `ZONES_REQUIRED` exist, with their
   interfaces, and that the interfaces the NAT policies name (`X1`) are the
   right ones. Back up the settings (*Export Settings*).
2. Log in by SSH as an administrator and paste the file. It starts with
   `configure terminal` (SonicOS 6.5 wants `configure`: change the first
   line) and ends with `commit`, which applies everything at once.
3. Read what the firewall answers: a command it refuses does not stop the
   others. Then compare the access rules of each pair of zones, and the NAT
   policies, with the summary of the report.
4. New access rules go above the default rule of their pair; each pair ends in
   a rule of FWShift that denies. A NAT policy that is there already, such as
   the default NAT policy of the firewall, may come first.
5. An object of the same name as one the firewall has is changed or refused:
   convert with `--target-prefix` to keep them apart.

### WatchGuard

> **The file has never been opened in Policy Manager.** WatchGuard publishes
> no schema of it; the elements follow the published readers of the format,
> and the words for the action of a policy (`Allow`, `Deny`) are assumed
> (`WATCHGUARD_LOAD`).

The output is **not a configuration to restore**: a restore replaces the
whole configuration, and this file holds no interfaces and no system
settings.

1. Save the configuration of the target from Policy Manager (*File > Save >
   As File*) and keep a copy.
2. Make sure the interfaces listed in `INTERFACES_REQUIRED` exist under those
   names.
3. Copy the entries of each list of the output (`address-group-list`,
   `service-list`, `nat-list`, `alias-list`, `abs-policy-list`,
   `policy-list`) into the list of the same name in the saved file, and set
   `auto-order-enabled` to `0` there, so the order of the policies stays the
   order of the file. An entry of the same name as one the file has collides:
   convert with `--target-prefix` to keep them apart.
4. Open the result in Policy Manager. Check that it reads every policy, and
   compare the policies and their order with the summary of the report.
5. Save it to the Firebox from Policy Manager.

### Barracuda

> **The script has never run against a CloudGen Firewall.** The calls and keys
> follow the examples in Barracuda's documentation; those the report lists
> under `BARRACUDA_LOAD` (the keys of a service object, the interface of an
> entry, the IP version and actions of a rule other than block, the limits of
> names) are assumed.

1. Switch on the REST API and create an access token (section 3). Make sure
   the interfaces listed in `INTERFACES_REQUIRED` exist under those names.
2. Read the calls first: `DRY_RUN=1 sh rules.sh` prints them and makes none.
3. Run it: `BARRACUDA=https://fw.example.net:8443 TOKEN=<token> sh rules.sh`.
   It needs curl 7.76 or later. The token goes to curl in a file that only the
   script reads and that is removed at the end.
4. The script stops at the first call the firewall refuses and shows its
   answer. What was created before it stays; of the rules, only those before
   the refused one are active, above the rules the firewall had. An object or
   rule of the same name as one the firewall has is refused: convert with
   `--target-prefix`.
5. Look at the rules of the firewall below the converted ones, then activate
   FWSHIFT-BLOCK and FWSHIFT-BLOCK-v6 (`BLOCK_RULE_INACTIVE`). Activate the
   ruleset as the firewall requires.

### Juniper SRX

> **The commands have never been loaded on an SRX.** Their form follows
> Juniper's documentation and a published reader of Junos; the report lists
> under `JUNOS_LOAD` what is assumed (names of up to 63 characters, `match
> from-zone`/`to-zone` in global policies, the predefined applications).

1. Make sure the zones listed in `ZONES_REQUIRED` exist, with their
   interfaces. The objects go into the global address book; an SRX that keeps
   address books in its zones (the older way) does not take both.
2. Load the file in configuration mode: `configure private`, then
   `load set terminal` and paste it (end with Ctrl-D), or copy it to the SRX
   and `load set /var/tmp/fwshift.set`.
3. `show | compare` shows what changes; `commit check` checks it.
4. New policies go to the end of their pair of zones, after the policies the
   SRX has there; global policies after those. Move them with `insert
   security policies from-zone A to-zone B policy NEW before policy OLD` where
   the SRX's own should not come first.
5. `commit confirmed 5`, test, then `commit`.

### After loading

Search the configuration for `FWSHIFT`: every placeholder object and every
rule the converter disabled carries that word in its comment or description.
(Not on a Device Manager, where such rules and objects are not written: there
the report is the list.)

## 11. Errors and troubleshooting

| Message | Cause and remedy |
|---|---|
| `configuration with several virtual systems; choose one with --vsys: ...` | Name one of the listed virtual systems. |
| `Panorama configuration with several device groups; choose one with --device-group: ...` | Name one of the listed device groups. |
| `configuration with several VDOMs; choose one with --vdom: ...` | Name one of the listed VDOMs. |
| `no <config> element found` | The XML is not a PAN-OS configuration export. |
| `not well-formed XML: ...` | The file is damaged or is not XML; a `set`-format file is not supported as input. |
| `the XML contains a DOCTYPE or entity declaration` | Exports of PAN-OS and of Sophos Firewall never do; the file is refused as a precaution. |
| `the archive holds no Entities.xml; expected the .tar of 'Backup & firmware > Import export'` | The tar file is not an export of a Sophos Firewall. A backup is not an export. |
| `the archive could not be read: ...` | The tar file is damaged: unpack it by other means and give FWShift the `Entities.xml`. |
| `no <Configuration> element found; expected the Entities.xml of a Sophos Firewall export` | `--from sophos` on XML that is something else. |
| `the archive holds more than one Entities.xml` | Unpack the archive and give FWShift the file that is meant. |
| `the XML holds several <Configuration> elements, or one inside another` | Two exports in one file. Convert them one by one. |
| `the answer of the firewall says that the login failed` | The file is what the XML API answered to a request it refused. It holds no configuration. |
| `the input is compressed (gzip, bzip2 or xz)` | Unpack it and give FWShift the file inside. A Sophos export is a plain `.tar`, which is read as it is. |
| `the input is compressed (a zip), and not the configuration export of a Firewall Device Manager as FWShift reads it (...)` | The one zip that is read as it is, is the export of a Device Manager. The message says what is wrong with this one: it is encrypted (export with `doNotEncrypt`), it holds several text files or none, it is damaged, or what it holds is something else. |
| `zone '...' carries a name that is a word of the Sophos format` | To Sophos: a zone called `Any`, `None`, `Original` or `MASQ`. `<Zone>Any</Zone>` is every zone there. Give the zone another name with `--zone-map`. The same message exists for the values of `--zone-map` and `--interface-map`. |
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
| `the input holds several access control policies (...): choose one with --policy` | Management Center source: name one of the listed policies. The same for `--nat-policy`. Where two policies have one name (two domains), the message gives their ids, which the option takes as well. |
| `access control policy '...' is not in the input (found: ...)` | `--policy` names a policy that is not there. |
| `N access rules do not say which policy they are in ...` | Rules without their `metadata` and `links`, next to several policies. Fetch the rules of one policy with `expanded=true` and leave the answers as they are. |
| `the input is the JSON of a Firewall Device Manager; read it with --from fdm` | `--from fmc` on the export of a Device Manager, or the other way round. Leave `--from` out. |
| `the input holds objects of a Firewall Management Center and of a Firewall Device Manager; convert them apart` | Two exports in one file. |
| `no Cisco Secure Firewall configuration found; expected ...` | `--from fmc` or `--from fdm` on JSON that holds none of their objects: an error message of the API, for instance, saved instead of an answer. |
| `no rules and no objects found in the input` | The JSON is of a Cisco manager and holds nothing of a policy. |
| `not valid JSON (after N complete documents): ...` | One of the saved answers is cut short or is not JSON: often an HTML error page, or a token that ran out half way. Fetch again. |
| `the zip is encrypted. Export the configuration with doNotEncrypt ...` | Device Manager source: the export was made with a key. Export again without, or unpack the zip with its key and give FWShift the text file. |
| `the zip holds N text files; the export of a Firewall Device Manager holds one` | Not an export of a Device Manager, or one that was repacked. Give FWShift the file with the configuration. |
| `the input is a zip; unpack it and give FWShift the JSON inside` | `--from fmc` on a zip. |
| `--target-policy '...' is not a name a Management Center takes for a policy` | Up to 50 letters, digits, spaces, periods, underscores and hyphens. |
| `--target-prefix takes up to 20 letters, digits, periods, underscores and hyphens` | Management Center or Device Manager target. |
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
| `not a SonicWall settings export: ...` | The file is neither the Base64 of an export nor its decoded keys, or it is empty. |
| `the settings export holds key '...' twice, with two values` | Two exports in one file, or an edited one. |
| `this is the configuration of an OPNsense firewall ...` | OPNsense is not read (section 3). |
| `not a pfSense configuration: the first element is <...>` | `--from pfsense` on XML that is something else, or the backup of one area only (it starts with `<filter>`, say). Back up area **All**. |
| `<...> occurs N times in one <...>` | pfSense source: an element that can be there once is there twice. pfSense does not read such a file either; it was edited by hand or two files were joined. |
| `--interface-address: '...' is not INTERFACE=ADDRESS/BITS` | Write the option as `--interface-address wan=198.51.100.7/24`. |
| `--interface-address: no interface '...' in the configuration; it has ...` | Name the interface as the configuration does, by name or description: the message lists them. |
| `--interface-address: two IPv4 addresses for '...'` | One address per IP version and interface. |
| `--interface-address is for a pfSense or SonicWall source` | The option was given for another source. |
| `not a configuration of a Firebox: the first element is <...>, not <profile>` | `--from watchguard` on XML that is something else. |
| `the configuration holds no <abs-policy-list>: is it the file Policy Manager saves?` | WatchGuard source: the XML starts like a configuration and holds no policies. Save it again with *File > Save > As File*. |
| `alias '...' is defined twice` | WatchGuard source: two aliases, address groups or services of one name. Policy Manager does not save such a file; it was edited by hand or two files were joined. |
| `the aliases of the configuration hold more than 200000 members in all` | Aliases that name each other many times over. Not converted. |
| `zone '...' cannot be the name of a Firebox interface here` | To WatchGuard: a zone named like an interface class of Fireware (`Any`, `Firebox`, `Any-Trusted`, ...) or holding characters a name cannot have. Give it another name with `--zone-map`. |
| `no rules and no objects of a CloudGen Firewall found; ...` | `--from barracuda` on JSON that holds no forwarding rules and no network or service objects of the REST API. |
| `rule '...' is in the input twice` | Barracuda source: the answer of the rules was saved twice, or two pages overlap. The same for network and service objects. |
| `an item of a list of rules is not a rule (not a JSON object)` | Barracuda source: the answer is damaged or is not one of the forwarding rules. |
| `the network objects of the input hold more than 200000 addresses in all` | Objects that name each other many times over, or a list nobody can mean. Not converted. |
| `not usable JSON: a string holds half of a UTF-16 pair ...` | A JSON input holds an escape (`\ud800` to `\udfff`) that is no character. The file is damaged. |
| `--interface-map: '...' is not the name of an interface of a CloudGen Firewall` | To Barracuda: the interface takes letters, digits, period, underscore, hyphen and colon. |
| `the configuration takes parts of its security policy or applications from groups ...` | Junos source: export with `show configuration \| display inheritance no-comments \| display set` (section 3). |
| `no 'security' part found ...` | `--from junos` on a configuration without security zones, policies or applications, or on part of one. |
| `line N: not a line of 'show configuration \| display set' ...` | A set-form file holds a line that is neither `set` nor `deactivate`. |
| `line N: '...' belongs to a file of commands ...` | The file holds `delete`, `insert` and the like: it is a script of commands, not a configuration. |
| `line N: the configuration ends inside a statement` | A configuration in braces with a `{` that is never closed, or no `;`: cut short. |
| `line N: blocks nested more than 64 deep` / `two lists in one statement` | A configuration in braces that no SRX writes. |
| `zone '...' cannot be the name of a security zone of an SRX` | To Junos: give the zone another name with `--zone-map`. |
| `--target-nat-zone: '...' is no interface a pfSense rule can name` | pfSense target: give `wan`, `lan`, an `optN` or the name of an interface group. |

**Most rules are "needs review".** Read the first finding of a few rules. A
single cause usually explains many: applications missing from the port table
(`--app-map`), an object type that is not converted, FortiOS attributes
FWShift does not know, or a Check Point export without `details-level full`
and `dereference-group-members true`, in which the objects are names without
content.

**Rules from a Management Center are disabled, with "not in the input in
full" or `RULES_NOT_EXPANDED`.** The lists were fetched without
`expanded=true`, or the objects were not fetched at all: the input holds
names without content. Section 3 has the calls.

**The script for a Management Center stops with "exist already".** Names of
the policy are taken on the target. Nothing was created. Convert again with
`--target-prefix`, or, when the objects on the target are the same objects
from an earlier run, undo that run first (`--undo`).

**A conversion from a Management Center says `INHERITANCE_UNKNOWN`.** The
input does not say whether the policy has a parent. Add the answer of
`policy/accesspolicies/<id>/inheritancesettings` to the input (section 3).

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

**Rules from a pfSense are disabled, with "give it with
--interface-address".** The interface gets its address by DHCP, PPPoE or
from another interface, and the configuration does not hold it. Give it
(section 3).

**Rules for a pfSense pass more or less than the source.** Like an ASA, a rule
of pfSense is for the interface traffic arrives on and cannot name the one it
leaves by. Give the networks of every zone with `--zone-network`, and check
`EGRESS_INTERFACE` and `FLOATING_AFTER_NAT` in the report.

**The output is larger than expected.** Every object of the source is
converted, used or not; a FortiOS backup alone defines some ninety default
services. Use `--prune-unused`.

**The report mentions `0.0.0.0/0` where the source says `all`.** That is
deliberate: see *IPv4 and IPv6* in section 8.

## 12. Limits

* The emitted syntax follows the vendors' documented formats. Only iptables
  output has been loaded into the real thing (a Linux kernel with iptables
  1.8.10, nf_tables backend; filter rules, not NAT); nothing has been
  validated on PAN-OS, FortiOS, ASA, Sophos or pfSense devices, a Check Point
  management server, a Cisco Secure Firewall Management Center or Device
  Manager, or across versions.
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
* Sophos Firewall: SFOS 18 and later. Users and groups, schedules, web,
  application and intrusion prevention policies, traffic shaping, Security
  Heartbeat, web server protection rules, MAC hosts, country groups, device
  access and VPN are not converted. Zones and interfaces are not created. A
  NAT rule matches interfaces: one that is read without the interfaces of the
  export, or written without `--interface-map`, applies to more traffic, and
  is reported. Linked NAT rules are read as rules of their own. Nothing has
  been imported on a Sophos Firewall. The element names of a NAT rule's match
  and the first line of the file are not in the documentation FWShift was
  written from; `DEVELOPMENT.md` lists what is assumed.
* Cisco Secure Firewall: one access control policy (with the policies it
  inherits from, as far as the input says that it inherits), its prefilter
  policy and one NAT policy of one domain per run. Application, URL, user, VLAN, security group tag and dynamic object
  conditions, time ranges, intrusion, file, SSL, identity and DNS policies,
  what happens inside a tunnel that a prefilter rule hands on, object
  overrides per device, platform settings, routing and VPN are not converted.
  A Fastpath rule below a prefilter rule that hands the same traffic to the
  access rules is not converted. Written for a Management Center: a new
  policy, never a change to an existing one; rules go to the mandatory
  section; prefilter rules of a Cisco source become access rules. Written
  for a Device Manager: no rule that is disabled or could not be converted,
  no zones, no IP in IP and IPv6 in IP as protocols (a rule that names one of
  them next to other services is left out whole, a blocking rule too: the
  prefilter default "block all tunnel traffic" of a Management Center is such
  a rule), NAT rules with single ports only. The JSON of both managers, the calls of the script and the
  format of the import file are taken from documentation and from Cisco's
  published tooling; nothing has been run against a Management Center or a
  Device Manager. `DEVELOPMENT.md` lists what is assumed.
* SonicWall: SonicOS 6.5 and 7 in Classic mode, from the settings export,
  which SonicWall does not document: the keys read are those of the published
  readers of the format. Not converted: ICMP service objects, IPv6 and MAC
  address objects, users, schedules, source port services, Geo-IP and botnet
  filtering, Policy mode. Written: TCP and UDP services and ICMP echo only;
  objects, groups, rules and NAT policies, not zones or interfaces. Nothing
  has been run on a SonicWall.
* WatchGuard: Fireware 12, from the configuration file of Policy Manager,
  which WatchGuard does not document: the elements read are those of the
  published readers of the format. Not converted: network dynamic NAT and
  1-to-1 NAT (read and written), users in the To list, VPN interfaces,
  schedules, proxy actions, policy-based routing. In automatic policy order
  the order is the file's, not the Firebox's. Written: the policy part of a
  configuration file, to merge into one of the target, with static NAT only
  as an action of a policy that allows exactly its traffic. Nothing has been
  opened in Policy Manager or loaded on a Firebox.
* Barracuda: CloudGen Firewall 8.0 and later, from saved answers of its REST
  API, which Barracuda documents by examples only. Not converted: rule lists
  (Cascade), NAT (Dst NAT, Map, connection objects), App Redirect, the
  mismatch policy, schedules, users, the host firewall, a Control Center,
  geolocation, wildcard and external objects. Written: a script of REST calls,
  zones only as interfaces of source entries or networks, no NAT, host names
  as placeholders; the rule that blocks what no rule matches is created
  deactivated. Nothing has been run against a CloudGen Firewall.
* Juniper SRX: Junos OS, the root system, from `display set` or the
  configuration in braces. Not converted: logical systems and tenants,
  unified policies (`dynamic-application`), users (`source-identity`), URL
  categories, schedulers, policy-based VPN, the zone `junos-host`, routing
  instances in NAT, wildcard addresses, predefined applications FWShift does
  not know. Written: set commands for the global address book, applications,
  policies and NAT. Nothing has been loaded on an SRX.
* pfSense: 2.6 and later; OPNsense is not read. Schedules, URL table
  aliases, policy routing, tags, limiters and shaping, match rules, IPv6 NAT,
  NPt, bogon networks, the captive portal, bridges and the rules of packages
  and of pfSense itself (except *Block private networks*, port forwards that
  pass by themselves and automatic outbound NAT) are not converted. A port
  forward from a range of ports to another range is not converted. *This
  Firewall* is the addresses the configuration holds, which may be fewer than
  the firewall has. What pfSense makes of its configuration is taken from its
  source code and checked against a model written for the tests, not against
  pf. Written for pfSense 2.7 and later: aliases, NAT and rules, no
  interfaces, groups, virtual IPs or schedules; a restore replaces each area
  whole. A rule written for traffic to a zone needs `--zone-network`, as for
  an ASA; a rule that passes traffic to any address leaves the firewall
  itself out. Nothing has been restored on a pfSense.
* The running configuration of an FTD device, read as an ASA configuration,
  shows only what the device was given. Rules with application, URL or user
  conditions come out disabled; for those the policy in the manager is the
  source (`--from fmc`, `--from fdm`).
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
| `NO_LOG` | low | A rule that does not log. PAN-OS, Check Point and Sophos sources only: there the model holds whether a rule logs. | off, accept, report |
| `NO_PROFILE` | low | An allow rule without a security profile. PAN-OS, FortiOS and Sophos sources only. | off, accept, report |
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
| `UNUSED_RULE` | medium | An allow rule that the hit counters (below) or the logs (section 15) prove unused. | off, accept, report, disable |
| `UNUSED_RULE_OBJECT` | low | Objects in the cells of a used allow rule that no logged connection used (section 15). | off, accept, report |
| `UNUSED_RULE_SERVICE` | low | Services of a used allow rule that no logged connection used (section 15). | off, accept, report |
| `NO_USAGE_EVIDENCE` | info | A rule whose use cannot be told: it has no counter while other rules have one, its counter of 0 has counted for fewer than 90 days or for a time that is not known, or it does not come from every firewall the rule may be on; or the logs of the window prove nothing about it (section 15). | off, accept, report |

The level of `ANY_ANY_ANY`, `ANY_SERVICE` and `ANY_TO_ANY` is one lower for
a rule whose zones keep it to a part of the firewall: there is a zone it
neither comes from nor goes to, or it is for traffic inside a zone. A rule
from one zone to *every* other zone
names zones without being kept anywhere, and keeps its level: that is what
every access list on an ASA or a chain on iptables looks like.

Only enabled rules are looked at. The audit knows what a policy *says*; how
it is used only where the firewall's hit counters are given (below). Which
zone is the trusted one is not in a configuration.

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

### Hit counters

A firewall counts how often each rule matched. Where the counters are given,
the audit names the allow rules that never matched (`UNUSED_RULE`):

* **Check Point:** the counts are in the rulebase when it was exported with
  `show-hits true` (section 3).
* **PAN-OS and FortiOS:** the counters are an answer of the firewall's API,
  given with `--hits FILE` (section 3). Repeat `--hits` for several
  firewalls: their counters are added up.

```sh
fwshift audit running-config.xml --hits hits-fw1.xml
```

```
FWShift audit
  source: panos (vsys1)
  security rules: 42 (2 disabled), NAT rules: 6
  hit counters: hits-fw1.xml (vsys vsys1): counters of 40 rule(s); it also counts 1 rule(s) the policy does not have ('test-rule'): are the counters and the configuration from the same moment?
  ...
  [medium] UNUSED_RULE: rule 'old-ftp' allows traffic from zone trust to zone dmz, and its hit counter (hits-fw1.xml (vsys vsys1)) is 0 from 2026-02-11 to 2026-09-30 at least. Check that the counters cover every firewall the rule is on
```

A counter is matched to its rule by what the firewall itself calls the rule:
the name on PAN-OS, the uuid (or else the policy ID) on FortiOS, the uid on
Check Point. A counter that names a rule the policy does not have is listed
in the header, never put on another rule.

A zero is evidence only for the time the counter has counted, from its start
to the moment the counters were read. No answer records that moment; the
latest time the answer shows stands in for it, and is never later than it, so
a period is never taken longer than it was. Each answer is measured by its own
times. The start:

* **PAN-OS** says it: the latest of the last reset of the counter, the
  creation and the last change of the rule.
* **Check Point** says when the rule was created and last changed
  (`meta-info`, part of `details-level full`), but keeps counts for a period
  only ('Keep Hit Count data up to', 3 months unless changed). The start is
  the later of the change of the rule and the earliest first hit of any rule
  in the export, which is the earliest time the counts are known to reach
  back to. An export in which no rule was ever hit tells neither.
* **FortiOS** does not say. A FortiGate starts again when its counters are
  cleared, and a model without a disk when it restarts.
* `--hits-since YYYY-MM-DD` (or `"hits_since"` in the configuration file) is
  your word that the counters have counted since that day, where they do not
  say so themselves. It never moves a start that the counter gives earlier
  than a later one it gives.

Then:

* **Long enough** (at least 90 days, the threshold `usage_days`): `UNUSED_RULE`,
  with the period it covers: "0 from 2026-07-01 to 2026-09-30 at least".
* **Too short, or not known**: `NO_USAGE_EVIDENCE`, which says which.
* **Not every firewall.** Counters of one firewall for a Panorama device group
  cannot show that a rule pushed to several firewalls is unused anywhere; with
  several answers, a rule that one of them does not count is not known to be
  unused on that firewall: `NO_USAGE_EVIDENCE`. The same answer given twice is
  refused (it would count everything twice).
* **No counter.** A rule without a counter, where other rules have one, gets
  `NO_USAGE_EVIDENCE`.

A blocking rule gets no `UNUSED_RULE`: that nothing tried to get past it does
not mean it is not needed. `UNUSED_RULE=disable` writes unused rules disabled
in a conversion. The findings in JSON carry the identifiers of the rule on the
source (`source_ids`), so that a ticket can name the rule the firewall knows.
Usage per object and service comes from the logs (section 15).

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
  "thresholds": {"wide_network_v4": 8, "wide_network_v6": 32, "wide_ports": 1024, "usage_days": 90},
  "services": {
    "risky": {"telnet": ["tcp/23"], "rdp": ["tcp/3389", "udp/3389"]},
    "industrial": {"modbus": ["tcp/502"]}
  },
  "applications": {"risky": ["telnet", "ms-rdp"], "industrial": ["modbus"]},
  "fail_on": "high",
  "hits_since": "2026-01-01",
  "unchanged_since": "2026-01-01"
}
```

`hits_since` is `--hits-since` (section 13, *Hit counters*), `unchanged_since`
is `--unchanged-since` (section 15).
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

* It reads the policy, and the traffic as the hit counters of the firewall
  count it (per rule), or as its logs show it with `--usage-store` (per rule,
  object and service; section 15).
* Zones have no rank in a configuration. `ANY_SOURCE` from the Internet and
  from the server network look the same.
* `NO_LOG` and `NO_PROFILE` are only raised where the model holds what the
  rule does: logging for PAN-OS, Check Point and Sophos, profiles for PAN-OS,
  FortiOS and Sophos. On FortiOS the default of a policy, `logtraffic utm`, logs
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

## 14. The zone matrix

The audit asks rule by rule whether a rule is too wide. The matrix asks the
question the other way round: **what can this zone reach in that zone, and
which rules let it?** That is the view of a zone and conduit review (IEC
62443), of a segmentation check before an audit, and of anyone who has to
answer "can the office network talk to the PLCs?" from a rulebase of a
thousand lines.

```sh
fwshift matrix running-config.xml
```

```
What each zone may reach (rows: from, columns: to)
           trust             untrust           dmz               ot
  trust    any               app:web-brow… +2  tcp/80 +6         app:modbus +1
  untrust  -                 any               app:ssl app:smtp  -
  dmz      -                 app:dns app:ssl~  -                 -
  ot       -                 -                 -                 any
  -  nothing is allowed     any  every service     +N  and N more     ~  at most this (see the notes)

Conduits
trust -> trust (inside the zone)
  allowed: any
  by default, what no rule decides: any
trust -> untrust
  ...
trust -> dmz
  allowed: tcp/80, tcp/443, tcp/8080, tcp/8443, tcp/9000-9010, app:ssh, app:ping
  rule 'Admin-SSH': admin-range -> dmz-servers: applications ssh on their default ports (users example\netadmins)
  rule 'App-Server-Ports': lan-net, lan6-net -> web-1: tcp/80, tcp/443, tcp/8080, tcp/8443, tcp/9000-9010
  rule 'Not-From-Guests': not 10.10.200.0/24 -> all-servers: applications ping on their default ports
trust -> ot
  allowed: app:modbus, app:siemens-s7
  industrial protocols: modbus (rule 'Engineering to PLCs'); siemens-s7 (rule 'Engineering to PLCs')
  rule 'Engineering to PLCs': eng-station -> plc-net: applications modbus, siemens-s7 on their default ports
...
```

The grid is the overview; under *Conduits* every pair of zones with anything
allowed is listed with its rules, in the order of the policy. `--summary`
leaves the rules out, `--json` and `--csv` give the same content for a
program or a spreadsheet (a line per rule and conduit). A rule that is in
every conduit with the same content (a rule for any zone, in a policy with
many zones) is listed once, under *In every conduit*; JSON and CSV repeat it.

### What a cell says

A cell holds every service that the policy allows from **some** address of
the one zone to **some** address of the other. It does not say that every
address may: the rules under *Conduits* say who.

* A rule is shown with what the **blocking rules above it** leave of it. A
  rule "any service" under a rule that blocks telnet is shown as `any except
  tcp/23`.
* Rules that **never match** are not shown (the audit names them), nor are
  disabled rules.
* **By default**: where the policy lets through what no rule decides (inside
  a zone on PAN-OS, everywhere on a ruleset whose `FORWARD` policy is
  `ACCEPT`), a cell shows what is left for that default once every rule took
  its part. An iptables ruleset is for one IP version: its default is shown
  for that version, and a note says that the other is not in the file.
* `app:NAME`: the rule allows an application, not ports. Which ports that is
  on the wire is not looked up.
* `svc:NAME`: a service of the source that FWShift cannot read (an
  application or category object of the vendor). The rule is listed with the
  name, and not as open for every service.
* Rules for **users, URL categories or a schedule** are listed with that
  condition; the cell counts them in full.
* The lines *cleartext or remote administration* and *industrial protocols*
  use the lists of the audit (and of `--audit-config`, if given).
* `(other zones)`: the zones the policy does not name. A rule from or to
  `any` zone reaches them too; the row and column appear when a rule does,
  or when everything between zones is open by default.

**Of the rules it read, the matrix shows at most what they allow, never
less.** Where a rule cannot be read exactly (a host name, a dynamic group,
an object or rule the parser reported as approximated, a criterion that is
not in the model), it is shown with everything it might allow and marked
`~`. A blocking rule that cannot be read exactly takes nothing out of the
matrix. For the question "can A reach B", a conduit that is shown and does
not exist costs a look; a conduit that exists and is not shown is the
mistake.

What FWShift did **not** read is not in the matrix, and the matrix says so
under *From reading the configuration*: tables a parser does not convert (a
FortiOS `policy6` or `local-in-policy`), traffic the source lets through
outside its rules (VPN traffic past the access lists of an ASA, the implied
rules of Check Point), and, under *Not in the matrix*, rules that could not
be read at all. Read those lines before you read "nothing is allowed".

### Zones of your own

The zones of a zone model are seldom the interfaces of one firewall: one
interface carries three VLANs, a Check Point policy has no zones at all.
With `--network-zone` the matrix is drawn between zones that you give as
networks:

```sh
fwshift matrix running-config.xml \
    --network-zone office@trust=10.10.0.0/16 \
    --network-zone dmz@dmz=10.20.0.0/24 \
    --network-zone plant@ot=10.30.0.0/16 \
    --network-zone internet@untrust=0.0.0.0/0,::/0
```

```
              office            dmz               plant             internet
  office      any               tcp/80 +6         app:modbus +1     app:web-brow… +2
  dmz         -                 -                 -                 app:dns app:ssl~
  plant       -                 -                 any               -
  internet    -                 app:ssl app:smtp  -                 any
```

* `NAME=NETWORK[,NETWORK...]`: addresses, prefixes or ranges, IPv4 and IPv6.
  The option is repeatable, also for one zone: its networks, and the zones
  it lies behind, are taken together.
* Of two networks, one inside the other, **the smaller one decides**, as a
  route would: `internet=0.0.0.0/0,::/0` is "everything that is in no other
  zone". Without such a zone the rest is shown as `(elsewhere)`. Two zones
  that share addresses in any other way are refused.
* `NAME@ZONE=...` says that the networks lie **behind zone `ZONE` of the
  policy** (several zones: `NAME@ZONE1,ZONE2=...`). A rule is then shown for
  that zone only if it is for one of those zones of the policy. Without
  `@ZONE` FWShift does not know where the networks lie, and shows a rule
  wherever its addresses reach: a rule from `any` address is then in every
  row, whatever zone it names. Say `@ZONE` wherever the policy has zones.
  A zone that the policy does not name is taken as one of the zones nobody
  names (an interface without a rule is not in an iptables ruleset): only
  rules for `any` zone are shown for it, and a note asks you to check the
  spelling.
* **`(ZONE: other addresses)`.** A zone of the policy that none of your
  zones is said to lie behind gets a row and a column of its own, with
  everything its rules allow (unless a zone of yours without `@ZONE`, or
  `(elsewhere)`, takes the addresses). The same row takes a rule that
  *names* an address which, by your networks, lies behind another zone than
  the rule is for: a rule from zone `inside` for a server address, a rule for
  a public address that is routed into the DMZ without NAT. The networks you
  give need not be all there is behind a zone, and such a rule is not left
  out for it. A rule for `any` address names no such address, and is shown
  for the zones you gave.
* **Traffic inside a zone of the policy** that the firewall allows by default
  is shown between zones of yours that are known (`@ZONE`) to lie behind that
  zone. For zones without `@ZONE` it is **not in the matrix**, and a note
  says so.
* **Destination NAT.** On PAN-OS and Check Point a rule names the published
  address. The matrix shows such a rule also for the zone of the server
  behind it, marked *through NAT rule ...*, for every enabled NAT rule that
  translates a destination, whatever its shape; where the translated address
  cannot be read (a host name), for every zone the traffic could end in,
  marked `~`. On FortiOS, iptables and ASA the rule is for the server
  already. A FortiOS policy that names a virtual IP is taken as traffic to
  the mapped address, and a blocking policy for the same virtual IP above it
  takes its part.

### Limits of the matrix

* It is read from the configuration. Routing, the networks that really lie
  behind an interface, and whether anything listens on a port are not in it.
* It shows what is allowed, not what is used.
* Source NAT is not applied: the source zone is where the traffic comes
  from.
* The effect of a destination NAT on the *port* is not shown: a rule is
  listed with the services it names.
* Applications are names. `app:ssl` and `tcp/443` in one cell are not merged.
* A rule that falls into more than 4096 pieces under the blocking rules above
  it is shown as written and marked `~`.
* A policy of 2000 rules and 30 zones takes about a second. A rule for any
  zone is in every cell: a thousand such rules on a firewall with fifty
  zones take ten seconds, a gigabyte of memory, and 280 MB as JSON. The text
  stays small (such rules are listed once); `--summary` is smaller still.
* The matrix is new in 0.5 and has, like everything else, been tested on
  synthetic policies only.

## 15. Rule usage from logs

The audit knows what a policy allows; the hit counters know which rules were
hit. The logs know more: which objects and services inside each rule the
connections used. `fwshift usage` reads them, as fwanalyser did for Check
Point, for a Check Point, PAN-OS, FortiOS or iptables policy
(`docs/RULE_USAGE.md` has the design and the plan).

```sh
fwshift usage checkpoint.json --logs gw-edge-2026-09.log --store usage.db
fwshift usage checkpoint.json --logs gw-edge-2026-10.log --store usage.db --html usage.html
fwshift usage checkpoint.json --store usage.db --since 30d
```

```
FWShift usage
  source: checkpoint (Network)
  store: usage.db (logs from 2026-07-03 to 2026-09-30, 1 run(s))
  window: 2026-07-03 to 2026-09-30 (90 days)
  read now: 1 file(s), 538 line(s), 412 connection(s)
    90 not counted: an update of a connection logged before (Log Update)
    36 not counted: a firewall log that names no rule (an update, a packet out of state, a NAT event)
  gateway gw-edge: logs on 90 of 90 days
  rules installed on every target are judged by the logs of gw-edge; name a gateway that sent none with --gateway
  connections in the window: 412, attributed to a rule of the policy: 412

Findings
  [medium] UNUSED_RULE: rule 'DMZ users' allows traffic from any zone to any zone, and the logs of gw-edge show no connection that the gateway attributed to it from 2026-07-03 to 2026-09-30, with logs on every day
  [low] UNUSED_RULE_OBJECT: rule 'DNS' of its sources 'dmz-net' had no connection from 2026-07-03 to 2026-09-30, out of 96 connection(s) through the rule
  [low] UNUSED_RULE_SERVICE: rule 'DNS' of its services 'domain-tcp' had no connection from 2026-07-03 to 2026-09-30, out of 96 connection(s) through the rule

Rules
  'DNS' (allow): 96 connection(s)
      source: lan-net 96, dmz-net 0
      destination: dns-servers 96, dns-1 96, dns-2 0, 192.0.2.54 0, 2001:db8:53::54 0
      service: domain-udp 96, domain-tcp 0
  ...
```

(`tests/data/checkpoint_sample.log` and its policy are the sample this comes
from.)

### Getting the logs

* **Log Exporter** (`cp_log_export`) sends the logs of the management or log
  server to a syslog server. Its default format, `syslog`, and the formats
  `splunk` and `cef` are read; keep the default set of fields, which carries
  the match table (`layer_uuid`, `match_id`, `parent_rule`, `rule_uid`).
  The read mode `semi-unified` (the default) is right: the updates it sends
  for a connection logged before (`Log Update`) are recognised and counted
  once. Log Exporter sends UTC.
* **show-logs** of the Management API answers with JSON in which each log has
  a `match_table` of rows; save the answers (all pages) in a file.
* Not read in this version: the CSV export of SmartConsole (it exports the
  rows on the screen only, and has no rule uid), `fwm logexport` (no rule uid
  is known to be in it), the gateway's own syslog (`Fields@2620`), and the
  Log Exporter formats `json`, `leef`, `generic`. Lines that look like Check
  Point's in such a format are counted as lines that could not be read
  (below). Reading the CSV export and `fwm logexport`, whose lines would be
  matched against the rules as iptables lines are, comes later.
* Relays may put a syslog header of their own in front of a line
  (`... CheckPoint[1234]: [action:"Accept"; ...]`); the line is read from its
  first field.
* **PAN-OS** sends the traffic logs of a rule to syslog (or Panorama) through
  the **log forwarding profile** of the rule; a rule without one sends none
  and proves nothing. The default format (BSD or IETF) is read, from PAN-OS
  8.1 on (fields are added at the end in each version), and so is the CSV
  export of the traffic logs (Monitor), which holds the logs of every rule.
  A rule logs at session end by default; a rule that also logs at session
  start gives two lines for one session, counted once. Rules are found by
  their UUID (9.0 and later) and by name. Log Forwarding with CEF or LEEF
  is a format of your own and is not read (a doubt).
* **FortiOS** sends the traffic logs of a policy only with `set logtraffic
  all`: the default, `utm`, logs the sessions a security profile looked at,
  and proves nothing for the others. The default format (`key=value`) is
  read, also behind a syslog header and as a FortiAnalyzer forwards it
  (`logver=` in front); `csv`, `cef` and `json` are not. Policies are found
  by `poluuid` and by `policyid`. The interim statistics of a long session
  (`long-live-session-stat`) and the start of a session whose end is logged
  are not counted again.
* **iptables** writes a line to the kernel log for each packet a `LOG` rule
  matches; syslog or the journal keeps it with a time and the host name:

  ```
  Oct 12 10:00:00 fw1 kernel: [12.3] fw-new IN=eth1 OUT=eth0 MAC=... SRC=10.10.4.20 DST=192.0.2.53 ... PROTO=UDP SPT=40000 DPT=53 LEN=40
  ```

  Give the files syslog writes (`/var/log/kern.log`, `/var/log/messages`), or
  `journalctl -k -o short-iso` (whose times carry their zone). The old syslog
  form has no year and no zone: give them with `--log-year` and
  `--log-offset`. `dmesg` keeps neither time nor host and is not read.
  Lines of `NFLOG` and `ULOG` rules go to ulogd, not to the kernel log, and
  are not read; nor are lines of `ebtables` or `TRACE`.
* For a policy that does not log every rule, the simplest way to the logs is
  one `LOG` rule for new connections at the top of `FORWARD`, after the rule
  that accepts established connections:

  ```
  -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  -A FORWARD -m conntrack --ctstate NEW -j LOG --log-prefix "fw-new "
  ```

  Every rule below it then logs its connections (a rule for new connections,
  or any rule once established and related packets are accepted above it). A
  `LOG` rule with `-m limit` logs some connections only, and logs nothing for
  the rules below it. A `LOG` rule without a state, or ahead of the rule that
  accepts established connections, logs every packet: then only TCP packets
  that open a connection (SYN alone) are counted, and lines of other
  protocols count as possible only (the report says so).

### How a connection is attributed

A connection counts for the rule **the gateway named** where its log names
one (Check Point, PAN-OS, FortiOS), and otherwise for the rule the policy
gives it (iptables), certain or possible (below).

1. A log line that names a rule is a connection of that rule, whatever blade
   wrote it (an Application Control log names the Network rule too) and
   whatever else it lacks: an address, a protocol or a port that is not in it
   counts as "not in the log", and then none of the objects or services of that
   cell is called unused. Each line has a match table: one row per layer the
   connection went through, outer first. The row of the layer the policy was
   read from is found by its uuid, whether that layer is ordered or itself an
   inline layer; rows of other ordered layers are passed over.
2. A rule that applies an inline layer is followed into it (`parent_rule` is
   the number of the rule applying the layer). The uids of the rules on the way
   name the rule of the model, which for a rule of an inline layer is the two
   combined (section 8). The implicit cleanup of an inline layer (a row with no
   uid) goes to the cleanup rule FWShift added for it; the implicit cleanup of
   the layer itself is the default of the policy, no rule.
3. A rule split into parts by its access roles (section 8): the part whose
   source holds the address and, for a part of users, where the log names a
   user. A part without connections of its own, of a rule whose other parts
   had them, is no unused rule: its sources are unused objects.
4. Inside the rule, every object of the source and destination that holds the
   address, through groups, each once; every service that holds the protocol
   and the port. An object with automatic static NAT counts its translated
   address as itself. A negated cell counts "outside the listed".
5. Where Log Exporter leaves a column short (a rule without a name, a layer's
   implicit cleanup without a uid) the uids are put on their rows only where
   their number fits; otherwise every rule they name counts as used, and nothing
   more is said about them.

Connections that name no rule of the policy are listed by reason: another
layer, the implicit cleanup of the layer, a rule the policy does not have (the
logs of another revision of it).

Where the uids of a Check Point log cannot be put on their rows, and where a
rule split by its access roles has more than one part that fits, the
connection is **possible** for each of those rules, not certain.

**PAN-OS and FortiOS** name a rule by its UUID and by its name or policy ID.
The UUID decides; a name or policy ID that belongs to a rule whose UUID is
another is another rule. Lines of another virtual system (when the policy was
read from a firewall's vsys) or another VDOM are not this policy's; lines of
`intrazone-default`, `interzone-default` and FortiOS policy 0 (the implicit
deny) are its default, no rule; a line naming a disabled rule is counted
apart. A line counts for one rule only, except:

* a PAN-OS session whose application changed: the rule its start names and
  the rule its end names both matched it, and both count;
* a PAN-OS start without its end in the same file, and a line with the flag
  of a temporary match for an application dependency (`0x2000`), are
  possible only;
* a rule found by name or policy ID, in logs of more than one firewall when
  no `--gateway` says which run the policy and the rule is not installed on
  the one that logged it (Panorama targets): possible only. A UUID is the
  rule's wherever it is logged.

The repeat count of a PAN-OS line is the number of sessions it stands for.
Where FortiOS logs a destination NAT (`trandisp` with `dnat`), a member of
the destination or the service that holds the address or port before or
after the translation counts as used.

**A log that names no rule** (iptables): the rules are taken in their order,
as the firewall takes them, each read as the audit reads it: what it surely
matches and what it might match. The connection is **certain** for the first
rule it might meet when that rule surely matches it. It is **possible** for
every rule from the first one it might, but not surely, match down to the
first one that surely matches it: a rule with a criterion the model does not
hold (`-m limit`, `-m recent`, a negation that cannot be read), with users or
a schedule, read approximately, or a port or zone the line does not give.
A connection no rule matches is the default of the policy. With `--json`,
each rule has `connections` (certain), `by_simulation` (how many of those
were worked out from the policy) and `possible`.

```
  connections in the window: 297, attributed to a rule of the policy: 271, possibly to one of several: 13
    297 named no rule and were matched against the rules of the policy as read (certain where the first rule they meet surely matches them, possible where it only might)
    13 not attributed: no rule matches it: the default of the policy
  ...
  'Rate limited mail' (allow): 0 connection(s), 13 possible
```

A rule with possible connections only is never called unused: it gets
`NO_USAGE_EVIDENCE`. Its objects and services count the possible connections
too. Connections are counted as possible only, for every rule, when the logs
may hold packets of connections already open (above), and when the logs come
from more than one host and no `--gateway` says which run the policy.

### When the logs prove something

A connection shows that a rule was used. No connection proves that it was
not only when:

* the rule logs its connections (Check Point: Track not None; PAN-OS: log at
  session end or start, and a log forwarding profile; FortiOS: `logtraffic
  all`);
* the export says when the rule was created or last changed (`meta-info`), and
  that was before the window, or `--unchanged-since` (`unchanged_since` in the
  configuration file) gives a day before the window where the export does not
  say (iptables never does);
* every gateway it is installed on (all gateways that sent logs, for a rule on
  every target; `--gateway` adds those that sent none) logged connections that
  name a rule on **every day** of the window, and at least one accepted
  connection in it (an exporter that sends drops only proves nothing for allow
  rules; a connection the policy certainly allowed counts as accepted). Logs of
  other blades and updates do not count as a day logged. For iptables, PAN-OS
  and FortiOS, the gateways are those given with `--gateway`, or every
  firewall that sent logs; for a policy of a virtual system or a VDOM, only
  the lines of that vsys or VDOM count as a day logged (each may send its
  logs elsewhere);
* no line of those gateways in the window could not be read (nor said that
  lines were lost: the kernel, the journal or rsyslog dropping some), and no
  line at all whose gateway and day could not be read;
* Check Point: the export gives the uid of the layer, and some connection in
  the window names a rule of it (otherwise these are not the logs of this
  policy).

Otherwise the finding is `NO_USAGE_EVIDENCE`, with the reasons. The same
holds for the objects and services of a used rule. A blocking rule gets no
finding of use.

With hit counters as well (`--hits`, or a rulebase exported with hits), a rule
that either shows used is used, a proof from either is enough for
`UNUSED_RULE`, and where the two disagree the report lists it (they rarely
cover the same period).

### The store

`--store` keeps the connections in one SQLite file, per day, gateway, rule,
source, destination, protocol, port and user, keyed by what the logs call the
rule, never by its number: a rule moved or renamed keeps its history, and a
store can be read against a later revision of the policy. A log file is
recognised by its content and read once. Beyond `--roll-up` addresses per rule
and side, addresses are kept as their /24 or /64; an object that such a network
overlaps counts as used, and the finding says so.

About 10,000 log lines a second are read (one core), also into a store that
holds millions of rows; evaluating a window takes seconds.

A file is recognised by its whole content: two exports that overlap count the
connections they share twice (the counts grow, no rule is called unused by
it). Lines that could not be read and have neither a gateway nor a day stay
against every window of the store; start a new store without the file that
held them. A file in which no line was a connection is not marked as read,
so a later version can read it.

### Limits

* Check Point, PAN-OS, FortiOS and iptables only. Narrower rules proposed from
  the use come in 0.17; the Check Point CSV export and `fwm logexport`, PAN-OS
  CEF and LEEF, and the FortiOS `csv`, `cef` and `json` formats later.
* PAN-OS: a rule that only the first packets of a session match, before the
  application is known (an application dependency), is named in the start log
  only; with logging at session start off, its use is not seen. Accept such a
  rule (`--audit-accept`) or turn on logging at session start for it.
* FortiOS: before 6.4, IPv6 policies (`policy6`) had policy IDs of their own;
  a log of one names an ID that may be an IPv4 policy's. Policies with a UUID
  are found by it.
* iptables: the lines carry no verdict, so the policy alone decides which rule
  a connection went through; a line of a packet that the policy as read does
  not let through (a ruleset changed since) counts for the rule the policy
  gives it now. The lines of the `nat` table, `INPUT` and `OUTPUT` are not
  connections of the policy. TCP lines whose flags cannot be read (a fragment)
  are counted as connections.
* Users are counted as the logs name them; a rule of user groups is not
  checked against them (the log names a person, the rule a group).
* The log formats are read as Check Point, Palo Alto Networks and Fortinet
  document them and as published parsers show them; no log of a real
  gateway was used. IPv6 logs and logs of
  implied rules were not seen anywhere.
