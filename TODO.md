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
areas Aliases, NAT and Firewall Rules for a restore, written; OPNsense is not
part of it, see below), **0.9.0, SonicWall** (the settings export of
SonicOS 6.5 and 7, read; commands of the SonicOS 7 command line, written),
**0.10.0, WatchGuard** (the configuration file of Policy Manager,
Fireware 12, read; its policy part, to merge into a configuration of the
target, written), **0.11.0, Barracuda CloudGen Firewall** (saved answers
of its REST API, read; a script of calls to that API, written; the
configuration backup is not readable), and **0.12.0, Juniper SRX**
(`display set` or the configuration in braces, read; set commands for
`load set`, written).
What each rests on and what nobody has checked on a device is in
the development log.

The brands that were planned are done. Not planned yet, and asked for often
enough to come next: nftables,
OPNsense (planned with pfSense, and left out of 0.8.0: its configuration
keeps aliases, automatic rules and parts of NAT elsewhere, and its rules have
other fields; FWShift refuses it with that reason), Huawei USG, Forcepoint, Stormshield,
MikroTik RouterOS, VMware NSX distributed firewall, cloud security groups
(AWS, Azure NSG).

## Rule usage

Which rules, objects and services of a policy are actually used, from the hit
counters of the firewalls and then from their logs: what fwanalyser did for
Check Point, for every platform FWShift reads. The design, the defects of
fwanalyser it must not repeat, and the open questions with the answers chosen
are in [docs/RULE_USAGE.md](docs/RULE_USAGE.md). One release per step;
0.13.0 is done (see the development log), the others follow:

1. **0.13.0, rule identity and hit counters** (done). The platforms' own rule
   identities on the rules of the model (Check Point rule, layer and parent
   rule UIDs, also for flattened inline rules; PAN-OS UUID and name; FortiOS
   `policyid` and UUID); install-on targets on the rule; Access Roles in the
   model instead of unsupported addresses; the audit checks `UNUSED_RULE`
   and `NO_USAGE_EVIDENCE` from hit counters (Check Point hits in the
   rulebase, PAN-OS and FortiOS through `audit --hits FILE`).
2. **0.14.0, `fwshift usage` for Check Point**: Log Exporter and CSV logs,
   a SQLite store, attribution by rule identity, usage per object and
   service (`UNUSED_RULE_OBJECT`, `UNUSED_RULE_SERVICE`), JSON and HTML output.
3. **0.15.0, simulation** where a log names no rule: first match on the
   audit's sets, certain and possible kept apart; iptables `LOG` lines.
4. **0.16.0, PAN-OS and FortiOS traffic logs.** Find out whether the FortiOS
   monitor counts IPv6 policies without `ip_version`.
5. **0.17.0, narrowing**: `WIDER_THAN_TRAFFIC`, with a narrower rule
   written through the emitters; never for deny rules.

## Audit and matrix

1. **The matrix before and after a conversion**, and of two configurations
   against each other: which conduits a conversion opened or closed. The
   pieces are there (`matrix.build` on the emitter's copy of the policy).
2. **A zone and conduit model as a file** (which zone may reach which, on
   which services) that a policy is checked against, with an exit status for
   a pipeline: the matrix as a gate, as `--audit-fail-on` is for the audit.
   This is the form in which an IEC 62443 zone model can be kept next to the
   firewall it is enforced on.
3. **The networks behind a zone from the source**, where the source knows
   them (interface addresses and routes of FortiOS, PAN-OS and ASA), so that
   `--network-zone NAME@ZONE=...` and `--zone-network` are only needed where
   the configuration does not tell.
4. **Ports of applications in the matrix**: an entry `app:ssl` could show the
   ports of the application map next to the name.
5. **Equivalence check as a command**: evaluate the source and the converted
   policy against each other and report every flow whose verdict changed. The
   simulators in the tests are the start of it, and so is the audit's set
   arithmetic: the difference of two policies is a set of boxes.
6. **Zone ranks** from a configuration file, so that "any source" from the
   Internet weighs more than from the server network.
7. **Hit counts** where a source exports them: allowed but never used. Now
   part of *Rule usage* above (0.13.0).
8. **Findings and matrix as SARIF, CSV or HTML**, for ticketing and
   code-scanning tools and for a report someone signs.
9. **NAT audit beyond shadowing**: overlapping translations, a published
   service without a rule that allows it, a rule for a published address
   whose NAT rule is gone.
10. The matrix on the output read back, for the targets FWShift can read.

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

## Project

1. Publish the wheel on PyPI from the release workflow (trusted publishing),
   once the output has been loaded on a device of each platform.
2. Run the release workflow on GitHub for the first time and correct what
   the dry run outside GitHub could not show (`DEVELOPMENT.md`, version
   0.6.1).
