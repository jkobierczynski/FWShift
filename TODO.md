# FWShift to-do

What is planned, in the order it is meant to be done. What has been done, and
why it was done that way, is in the development log of
[DEVELOPMENT.md](DEVELOPMENT.md).

## Firewall brands: one per release

Every brand gets a release of its own. A release is done
when the brand can be read **and** written, and has been through what every
platform so far went through:

- a parser to the neutral model and an emitter from it, with the semantics of
  the platform translated at its edges (rule lookup before or after
  destination NAT, first match or not, zones or interfaces, defaults);
- a synthetic sample configuration in `tests/data` (RFC 1918, 5737 and 3849
  addresses only; no configuration from a real network, anonymised or not)
  and golden files for its conversions, audit and matrix;
- tests with an oracle that walks packets through the source and the result;
- a review by the independent reviewer, its findings fixed, with regression
  tests;
- the manual (getting the configuration, how the platform differs, loading
  the output), the README table and the development log;
- a statement of what was verified and what was not. None of these platforms
  can be loaded in the environment FWShift is developed in: until someone
  runs the output on a device, each of them is "written from documentation".

The formats named below are what is expected to be the input, from memory.
The first step of each release is to confirm them against the vendor's
documentation, and to find out which export an administrator can actually
produce.

Done: **0.6.0, Sophos Firewall** (SFOS 18 and later; the `.tar` of *Import
export* or its `Entities.xml`, read and written), **0.7.0, Cisco Secure
Firewall** (the JSON of a Management Center's REST API and the configuration
export of a Device Manager, read; a script that loads a new policy through
the API of a Management Center and a file for the import of a Device Manager,
written), and **0.8.0, pfSense** (`config.xml` of 2.6 and later, read; the
areas Aliases, NAT and Firewall Rules for a restore, written; OPNsense came
later, in 0.24.0), **0.9.0, SonicWall** (the settings export of
SonicOS 6.5 and 7, read; commands of the SonicOS 7 command line, written),
**0.10.0, WatchGuard** (the configuration file of Policy Manager,
Fireware 12, read; its policy part, to merge into a configuration of the
target, written), **0.11.0, Barracuda CloudGen Firewall** (saved answers
of its REST API, read; a script of calls to that API, written; the
configuration backup is not readable), **0.12.0, Juniper SRX**
(`display set` or the configuration in braces, read; set commands for
`load set`, written), **0.18.0, nftables** (`nft list ruleset`, text or
JSON, read: every base chain at the forward hook, sets, maps, NAT; one table
for `nft -f`, written; checked against the kernel with real packets),
**0.19.0, VMware NSX distributed firewall** (the JSON of the Policy API,
read: categories, jump to Application, the default rule, groups by address,
path, segment or membership criteria, applied-to and direction as far as they
decide; the body of one hierarchical `PATCH`, written), **0.20.0, AWS
security groups** (the JSON of the AWS CLI for one VPC, read: groups as the
addresses of their interfaces, inbound and outbound rules, network ACLs,
public addresses; a script of AWS CLI calls that creates new groups, written:
each allow rule without the deny rules above it, at both ends), and
**0.21.0, Azure network security groups** (the JSON of the Azure CLI, the
REST API, an ARM template or Resource Graph, read: priorities, the default
rules, service tags, application security groups, the outbound and inbound
lists of two groups composed; an ARM template with a group per zone,
written), and **0.23.0, MikroTik RouterOS** (the output of `/export`,
RouterOS 6 and 7, read: the forward chains of `/ip` and `/ipv6`, custom
chains with returns taken away exactly, interface lists as zones, address
lists, the default accept and the `!dstnat` exception of the default
configuration, NAT; a script for `/import` whose chains are switched on by
one change, written), and **0.24.0, OPNsense** (`config.xml` of 24.7 to
26.7, read: both kinds of rule in the order of OPNsense's priorities, flags
as each series reads them, aliases with exclusions worked out as pf tables,
port forwards of both forms, Source NAT, 1:1 NAT, *received-on*; the areas
Aliases, NAT and Firewall Rules for one series, written), and **0.25.0,
Forcepoint NGFW** (the answers of the SMC REST API for one policy, fetched by
a read-only program FWShift writes, read: templates and insert points,
sections, Continue and Jump, zones and match expressions, expressions,
networks without broadcast, NONE cells, NAT rules; a program for the REST API
that creates elements and a new policy on a template, written), and **0.26.0,
Terraform for AWS and Azure** (`terraform show -json` of a state or a plan and the
raw state, read: the security groups, rules, network ACLs and members of
hashicorp/aws and the network security groups of hashicorp/azurerm, with the
echoes of a refresh taken once and the unknowns of a plan worked out from the
configuration or not converted; HCL that creates the groups, written), and
**0.27.0, Google Cloud** (the answers of gcloud for one VPC network, read:
VPC firewall rules, global and regional network firewall policies with
`goto_next`, the enforcement order, hierarchical policies when added, tags and
service accounts as the addresses of the instances, egress and ingress
composed between instances; a gcloud script that creates a new global network
firewall policy, written; the same from and to Terraform as
`terraform-google`), and **0.28.0, Cisco IOS and IOS XE** (`show running-config`
of a router, read: interface access lists in and out, numbered, named and IPv6,
object groups, the zone-based firewall with its zone pairs and class maps, NAT,
composed for each pair of zones where more than the inbound list decides;
commands for the zone-based firewall, written), and **0.29.0, Huawei USG**
(`display current-configuration` of a USG6000, USG6000E or USG9500, read:
security zones, address and service sets, `security-policy` with its
defaults, `nat server` before it and `nat-policy` after it; commands for the
system view, written), and **0.30.0, Stormshield SNS** (the ConfigFiles of a
firewall as the `.tgz` decbackup makes of a backup, read: interfaces, objects,
the active filter slot after the global one; a script of serverd commands that
writes one filter slot, written).
What each rests on and what nobody has checked on a device is in
the development log.

The brands planned in 2026 are done, and so is the zone and conduit model
with the equivalence check (0.22.0, under Audit and matrix below).

Still open for Forcepoint: the XML export of the SMC (refused until a real
export shows its format), the engine (aliases resolved per engine, zones with
their interfaces, element-based and default NAT), IPv6 NAT, and reading the
output back for `convert --compare`.

Next, one release each, in this order:

* **0.31.0, Cisco Meraki MX**: the layer 3 firewall rules of the Dashboard
  API, VLANs, 1:1 NAT and port forwarding.

Still open for Stormshield: the NAT rules of a slot (their syntax in the file),
and the serverd outputs (`CONFIG FILTER EXPLICIT ... output=xml`, `CONFIG OBJECT
LIST`) as a second input; checking on a firewall the syntax of rule lines
(disabled rules, ICMP types, the outgoing interface, lists and negation), the
layout of `slotinfo`, the IPv6 tokens of the commands that create objects and
how a bridge and its ports are matched; `Network_internals` with the networks of
static routes; NAT exemptions as a target; reading the script back for
`convert --compare`.

Still open for Huawei: virtual systems (each as its own policy, chosen as
`--vsys` is for PAN-OS); destination NAT of `nat-policy` and NAT of ranges;
rule groups, and whether a disabled group shows in display output; the ports of
the predefined services as `display predefined-service` prints them; checking on
a firewall the indentation of display output, the input form of IPv6 entries in
address sets and that `disable` is taken in a new rule; reading the output back
for `convert --compare`.

Still open for IOS: interface access lists as a target (for routers without the
zone-based firewall); NAT of the NAT virtual interface, outside NAT and route
maps; VRFs as separate routing tables; time ranges as schedules; checking on a
router which addresses the zone-based firewall sees under NAT, how an empty class
map matches and whether a list of remarks only is empty; reading the output back
for `convert --compare`.

Still open for Google Cloud: the region of a regional policy in the answer of
`get-effective-firewalls`; secure tags (resolved through the instances' tag
bindings), address groups; writing a regional policy or VPC firewall rules;
running the script against a project in a lab.

Still open for Terraform: reading the HCL back for `convert --compare` (it is
not JSON); the members of a group that another state attaches; a constant next
to a reference in one expression of a plan; module outputs as references;
`aws_security_group` with `name_prefix` in a plan; applying the output with
Terraform against a provider in a lab.


## Rule usage

Which rules, objects and services of a policy are actually used, from the hit
counters of the firewalls and then from their logs: what fwanalyser did for
Check Point, for every platform FWShift reads. The design, the defects of
fwanalyser it must not repeat, and the open questions with the answers chosen
are in [docs/RULE_USAGE.md](docs/RULE_USAGE.md). One release per step;
0.13.0 to 0.17.0 are done (see the development log); what is left:

1. **0.13.0, rule identity and hit counters** (done). The platforms' own rule
   identities on the rules of the model (Check Point rule, layer and parent
   rule UIDs, also for flattened inline rules; PAN-OS UUID and name; FortiOS
   `policyid` and UUID); install-on targets on the rule; Access Roles in the
   model instead of unsupported addresses; the audit checks `UNUSED_RULE`
   and `NO_USAGE_EVIDENCE` from hit counters (Check Point hits in the
   rulebase, PAN-OS and FortiOS through `audit --hits FILE`).
2. **0.14.0, `fwshift usage` for Check Point** (done): Log Exporter and
   `show-logs` logs, a SQLite store, attribution by rule identity, usage per
   object and service (`UNUSED_RULE_OBJECT`, `UNUSED_RULE_SERVICE`), JSON,
   text and HTML output.
3. **0.15.0, simulation** (done) where a log names no rule: first match on
   the audit's sets, certain and possible kept apart; iptables `LOG` lines.
4. **0.16.0, PAN-OS and FortiOS traffic logs** (done). Still open: whether
   the FortiOS monitor counts IPv6 policies without `ip_version`; PAN-OS CEF
   and LEEF, and the FortiOS `csv`, `cef` and `json` formats, once examples
   are at hand; the IPv6 policies of FortiOS before 6.4 (`policy6`).
5. **0.17.0, narrowing** (done): `WIDER_THAN_TRAFFIC`, with a narrower rule.
   Still open: writing a proposal as only the rule and its new objects into
   a running configuration, per vendor (position above the rule, the scope,
   no scaffolding), and reading proposals of other targets back in the tests;
   narrowing zones from the interfaces the logs give.
6. **Later, more Check Point logs**: the CSV export of SmartConsole and
   `fwm logexport` (no rule uid in them: through the simulation), the
   gateway's own syslog format (`Fields@2620`) and the Log Exporter formats
   `json`, `leef` and `generic`, once an example of each is found; users of a
   rule checked against the groups they belong to.
7. **iptables logs, more**: the lines of `NFLOG` rules as ulogd writes them;
   the verdict of a line from its log prefix, where the user says which prefix
   means what; `TRACE` lines, which name the rule.

## Audit and matrix

Done in 0.22.0: **the zone and conduit model as a gate** (`fwshift conduits`:
a JSON model of zones and conduits, a policy checked against it through its
matrix, a draft from a policy, exit status 3) and **the equivalence check**
(`fwshift compare` of two configurations; `convert --compare`, the output read
back and compared with the source): items 1, 2, 5 and 10 of the list before.

1. **The networks behind a zone from the source**, where the source knows
   them (interface addresses and routes of FortiOS, PAN-OS and ASA), so that
   `--network-zone NAME@ZONE=...` and `--zone-network` are only needed where
   the configuration does not tell.
2. **NAT in the comparison**: compare the NAT rules too, and the rules of a
   source that matches after destination NAT with the connection as it
   arrives, so that a published service is compared as a client sees it.
3. **More targets read back** for `convert --compare`: PAN-OS set commands,
   the Check Point script, SonicWall commands, the AWS and Barracuda scripts,
   the pfSense areas (with the interfaces of the configuration they go into);
   the ASA output with the interfaces and routes of the source.
4. **What labels hold**: schedules, custom URL categories and user groups are
   compared by name; read their definitions where the source has them.
5. **Ports of applications in the matrix**: an entry `app:ssl` could show the
   ports of the application map next to the name.
6. **Zone ranks** from a configuration file, so that "any source" from the
   Internet weighs more than from the server network.
7. **Findings, matrix, conduit check and comparison as SARIF, CSV or HTML**,
   for ticketing and code-scanning tools and for a report someone signs.
8. **NAT audit beyond shadowing**: overlapping translations, a published
   service without a rule that allows it, a rule for a published address
   whose NAT rule is gone.
9. **The conduit model, further**: security levels weighed against what a
   conduit carries (cleartext and remote administration into a zone of a high
   level), conduits of a site spread over several firewalls (one model, the
   policies of each), and a check of the replies a stateless target needs.

## Conversion

1. Correct services for port-translating destination NAT.
2. FortiOS output with per-policy NAT as an option.
3. PAN-OS `set`-format parser, which also allows a PAN-OS round-trip test.
4. Schedule objects (ASA time ranges, FortiOS and PAN-OS schedules); a
   user and group mapping file.
5. iptables `NETMAP`, read and written: it is what maps a network address
   for address, where `DNAT` to a range picks an address per connection.
6. Interface networks in the model (see *Audit and matrix* 3).
7. Sophos Firewall: users and schedules written back for a Sophos target
   (the element names are known, the objects must exist); linked NAT rules
   kept linked, and interface names of NAT rules kept as they are, Sophos to
   Sophos; IP lists written as IP lists. Find out whether a firewall rule
   sees the original or the translated service of a port translation.
8. Cisco Secure Firewall:
   * application conditions of a rule as App-ID names of the model (a table
     from Cisco's application names), so that such rules reach PAN-OS as
     application rules and port-based targets through the application map,
     instead of being written disabled;
   * Management Center to Management Center: intrusion, file and prefilter
     policies of a rule by name where the target has them, time ranges and
     users written back, rules in the default section, and the inheritance
     kept instead of flattened;
   * a blocking rule that can be written in part (the prefilter default
     "block all tunnel traffic" for a Device Manager, which has no name for
     two of its four protocols) written as that part, with the finding;
   * the script for a cloud-delivered Management Center (it logs in with a
     token of the Security Cloud Control tenant, not with a user);
   * interface types for the NAT rules of a Device Manager, from an export of
     the target given as an option, and its hardware model and software
     version from the same file;
   * static routes of the device, for the zone a translated destination is
     reached in;
   * the names of the predefined port objects of both managers with their
     values, so that a partial export that names `HTTPS` can be read.
9. A note where `--zone-map` merges two zones and a rule between them becomes
   a rule inside the merged zone (it then covers traffic inside each of the
   two as well). Found by the reviewer in round 15; older than 0.7.0.
10. pfSense:
    * schedules and virtual IPs written as well, for a full restore of
      `schedules` and `virtualip` (neither can be restored as an area);
    * port forwards from a range of ports to another range (the model has
      one port or the same range);
    * IPv6 NAT and NPt; outbound NAT without IP version also for IPv6;
    * URL table aliases from a file given as an option;
    * the outbound NAT form of 2.6 as an option for an old target;
    * the names `/etc/protocols` and `/etc/services` of FreeBSD hold, to
      read every service name and to keep alias names away from them (the
      web interface refuses those on the next edit);
    * leading spaces in values, which pfSense keeps and the parser strips;
      SCTP ports, which 2.6 ignores;
    * whether `no rdr` also ends 1:1 NAT for what arrives, and `no binat`
      outbound NAT (from pf, not checked), which decides how far such an
      exception reaches.
11. SonicWall: ICMP service objects, IPv6 and MAC address objects as an export
    stores them (from a real export); `priority` of NAT policies; users and
    schedules written back SonicWall to SonicWall; the zone of an address
    object kept SonicWall to SonicWall; Policy mode (SonicOSX).
12. WatchGuard: network dynamic NAT, 1-to-1 NAT and the NAT settings of a
    policy, read and written, once a real file shows where they are; the
    automatic policy order worked out (the precedence cascade of the Help
    Center) instead of reported; users, schedules and proxy actions written
    back WatchGuard to WatchGuard; a whole configuration file for a restore,
    from a configuration of the target given as an option.
13. Barracuda: Dst NAT, Map and connection objects, read and written, once
    the JSON of the API is known; rule lists (Cascade) read; hostname objects
    written; the PAR backup read, once a real one shows its format; a script
    that fetches the answers FWShift reads.
14. Juniper: logical systems and tenants; unified policies
    (`dynamic-application`) as App-IDs where the target has them; schedulers;
    rule sets of routing instances; the predefined applications taken from a
    real `junos-defaults`; NAT rule sets of several zones at once instead of
    one per zone or pair of zones.
15. Static NAT between address sets of different size is reported for ASA and
    Cisco Secure Firewall targets, which wrap around, and not for PAN-OS,
    where the commit fails.
16. NSX: the gateway firewall of Tier-0 and Tier-1 gateways, and its NAT;
    context profiles (layer-7 applications, FQDNs) as App-IDs where the
    target has them; the members of dynamic groups fetched (`.../groups/ID/
    members/ip-addresses`) by a script the manual names; the distributed
    firewall's logs for `fwshift usage`; one policy per category written,
    instead of one policy of category Application.
17. AWS: a CloudFormation template as a second output; the network ACLs
    written where a blocking rule is for a whole subnet; the members of a
    group kept by interface, so that the groups of the script follow
    interfaces; traffic to the VPC's own public addresses and through NAT
    gateways converted; VPC Flow Logs for `fwshift usage`; several VPCs, with
    peering, at once.
18. Azure: an interface behind a group of its own and one on its subnet
    converted as the two lists in turn (now each on its own,
    `AZURE_NSG_CHAIN`); Azure Virtual Network Manager's security admin rules
    read; VPN gateways between virtual networks; Bicep files themselves, and
    the template functions not worked out yet (`uniqueString`, `resourceGroup()`);
    NSG flow logs and VNet flow logs for `fwshift usage`; a target of Azure
    Firewall policies, which have zones and order of their own. The
    composition of two groups grows with the square of their rules: compose
    only the pairs whose networks are given.
19. Other emitters read `Zone.intrazone_allow = False` as "the policy's
    default" where the model means "denied inside the zone" (the Azure emitter
    was corrected in review round 29): look at each.

## Validation

1. Load `tests/data/expected/fortios_to_panos.set` on a PAN-OS VM,
   `panos_to_fortios.conf` on a FortiGate VM and `panos_to_asa.cfg` on an
   ASAv; record what each CLI rejects and correct the emitters. Work through
   the assumptions table of DEVELOPMENT.md. Compare `asa_sample.cfg` and the
   FTD text in `test_asa.py` with what real devices print.
2. Import `tests/data/expected/panos_to_sophos.xml` (as a `.tar`) on a Sophos
   Firewall in a lab: which entity does it stop at, if any, and what does the
   web console say then? Export a configuration with NAT rules and compare
   the element names of their match (`OriginalSourceNetworks`,
   `InboundInterfaces`, ...) and the first line of the file with what FWShift
   reads and writes; check exclusions of two kinds with a packet.
3. Run `*_to_checkpoint.sh` against a management server in a lab, and export
   a real rulebase with automatic NAT to compare with the sample. Extend
   `kernel_check.py` to NAT and IPv6, and run it on the legacy iptables
   backend.
4. pfSense, in a lab with 2.7.2 and a current version: restore
   `tests/data/expected/pfsense_to_pfsense.xml` and `panos_to_pfsense.xml`
   area by area and compare `pfctl -sr` and `pfctl -sn` with what the judge
   in `tests/helpers.py` expects; check the order of interface group rules on
   2.8, the service names of `getservbyname`, and what an empty area and an
   area restored without its aliases do.
5. SonicWall, on a lab firewall with SonicOS 7: paste `panos_to_sonicwall.cli`
   and `sonicwall_to_sonicwall.cli`, record what the command line refuses
   (`priority manual`, the name of a NAT policy, IPv6 and FQDN objects), and
   compare an export of the result with `sonicwall_sample.exp`: action codes,
   default rules, ICMP services.
6. WatchGuard, with Policy Manager and a Firebox (or FireboxV) on Fireware
   12: merge `panos_to_watchguard.xml` and `watchguard_to_watchguard.xml`
   into a saved configuration as the manual says, open it in Policy Manager
   and record what it refuses (the words of the action, the members of a
   static NAT action); save a configuration with dynamic and 1-to-1 NAT and
   automatic order and compare it with `watchguard_sample.xml`.
7. Barracuda, on a CloudGen Firewall VM (8.x or 9.x): fetch the answers of
   the manual and compare them with `barracuda_sample.json` (above all the
   service objects, `ipVersion`, `excluded`, rule lists); run
   `panos_to_barracuda.sh` with `DRY_RUN=1` and then for real, and record
   what the API refuses; check that names are told apart without regard to
   case.
8. Juniper, on a vSRX (21.4 and 23.4): check that `display inheritance
   no-comments | display set` is accepted and what it prints for groups;
   compare `show groups junos-defaults applications | display set` with
   FWShift's table of predefined applications; load
   `panos_to_junos.set.conf` and `junos_to_junos.set.conf` with `load set`,
   `commit check`, and compare `show security policies` and `show security
   nat` with the model; check names of 63 characters, `match from-zone` in
   global policies, and the order of NAT rule sets of one context.
9. Cisco Secure Firewall, on a Management Center and an FTD device in a lab:
   fetch a policy with the calls of the manual and compare the answers with
   `fmc_sample.json` (above all: how a policy says that it inherits, whether
   the list of a child holds the rules of its parent, the fields of a
   prefilter rule); run `fmc_to_fmc` and `panos_to_fmc` with `--dry-run` and
   then for real, and check the order of the rules, the names it refuses and
   what `--undo` leaves; export a Device Manager, compare with
   `fdm_sample.txt` (the container names of NAT rules, the protocol and ICMP
   names), and import `panos_to_fdm.json`.
10. The reviewer's oracles as tests: every pre-image of a real packet through
   a destination NAT (pre-NAT model to a post-NAT target, with several NAT
   rules for one address); same-kind round trips for FortiOS and iptables
   with rules that name both sides of a translation; `disable` across the
   two sides of destination NAT; the plain in-order reference for the audit.
   They were run from the reviewer's scratch directory and are not in the
   repository.
11. NSX, on an NSX Manager 4.x in a lab: export a policy with the call of
   the manual and compare it with `nsx_sample.json` (whether rules come
   inline or as children, the ids of the default policy and rule, the system
   services); send `panos_to_nsx.json` and `nsx_to_nsx.json` with `PATCH` and
   record what it refuses (`profiles`, ids of service entries, ids with
   `-`); check what a segment in a group matches, and that a connection is
   checked at both ends.
12. AWS, in a lab account: export a VPC with the calls of the manual and
   compare the answers with `aws_sample.json` (protocol names or numbers,
   ports of protocol 50, the ACL entries of a default ACL with IPv6); run
   `panos_to_aws.sh` and `aws_to_aws.sh` with `CHECK=1` and for real, and
   record what AWS refuses (descriptions, quotas); check which addresses a
   group reference covers (secondary, IPv6, delegated prefixes) and what
   `--dry-run` checks.
13. Azure, in a lab subscription: export the groups with the calls of the
   manual, with `az group export` and with `az graph query`, and compare them
   with `azure_sample.json` (the case of protocol names, the default rules,
   the ids of application security groups); deploy `panos_to_azure.json` and
   `azure_to_azure.json` with `what-if` and for real, and record what Azure
   refuses (names, descriptions, the 2,000 rules and the address limits);
   check whether `*` matches ESP, AH and other protocols, and what
   `VirtualNetwork` holds across peerings and gateways.
14. RouterOS, on a CHR (RouterOS 7) and a router with RouterOS 6: export it
   and compare with `routeros_sample.rsc` (how a long comment and a negation
   are wrapped, whether `print` numbering or `#error exporting` lines appear,
   protocol numbers such as `ipip`); import `panos_to_routeros.rsc` and
   `routeros_to_routeros.rsc` with `verbose=yes` and record what the router
   refuses (the check at the top, `?` and non-ASCII in comments, `dst-port`
   lists longer than 15, `icmp-options` with a code range, IPv6 ranges); switch
   the jumps on in Safe Mode and send packets through, the defaults and the
   `!dstnat` exception above all; check `icmp-options=8` without a code and
   `reject-with=tcp-reset` on a rule that matches more than TCP.
15. OPNsense, on a lab firewall of 26.7 and one of 25.7 (or 24.7): back
   them up and compare with `opnsense_sample.xml` (how the GUI writes empty
   flags, `quick` and the address lists of *Rules [new]*, the DNat form of a
   port forward after a save); restore `panos_to_opnsense.xml` and
   `opnsense_to_opnsense.xml` area by area (with `--target-version` of the
   firewall) and record what the restore and the filter reload refuse; send
   packets through: the order of the tiers, rules that are not quick on a
   tab, *received-on*, the link-local network in rules for IPv6, aliases with
   `!` entries, a disabled alias, Source NAT in each outbound mode, *Register
   rule*.
16. Forcepoint, with an SMC (7.x) and an engine in a lab: run the dump
   program against a policy built by hand and compare its answers with
   `forcepoint_sample.json` (the shape of rules, insert points, sections,
   match expressions, NAT values; what the XML export holds); load
   `panos_to_forcepoint` and `forcepoint_to_forcepoint` with the loader
   (`--dry-run` first) and record what the API refuses (names, a TCP service
   of ports 1 to 65535, an expression in a match expression, a rule posted to
   `add_after`); send packets through: Refuse on TCP, a network without
   broadcast, Continue logging, an exclusion of two elements.
17. Terraform, with Terraform 1.x and lab accounts of AWS and Azure: apply a small
   configuration of groups, separate rules, network ACLs and instances; convert
   `terraform show -json` of the state and of a plan that changes it, and compare with
   the CLI answers of the same resources; `terraform validate` and apply
   `panos_to_terraform_aws.tf` and `panos_to_terraform_azure.tf`, then convert the
   state they leave and compare it with the source.
18. The equivalence check on real changes: two exports of one firewall
   before and after a change made by hand, compared, and the differences
   checked against what was changed; a conversion loaded on a target, its
   running configuration exported again and compared with the source.

## Project

0. Security, after the outside review of October 2026
   ([docs/security/SECURITY_REVIEW.md](docs/security/SECURITY_REVIEW.md)): signed build provenance for the releases
   and protected release tags (repository settings); a journal and undo for the AWS and Barracuda scripts; a fuzzing
   suite for the parsers (truncated, huge and deeply nested inputs); a test of the loaders against a TLS server with a
   certificate that does not verify; a limit on the number of rules and objects read.

1. Publish the wheel on PyPI from the release workflow (trusted publishing),
   once the output has been loaded on a device of each platform.
2. Run the release workflow on GitHub for the first time and correct what
   the dry run outside GitHub could not show (`DEVELOPMENT.md`, version
   0.6.1).
