# FWShift to-do

What is planned, in the order it is meant to be done. What has been done, and
why it was done that way, is in the development log of
[DEVELOPMENT.md](DEVELOPMENT.md).

## Releases planned: one firewall brand per release

Every brand below gets a release of its own, in this order. A release is done
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
export* or its `Entities.xml`, read and written), and **0.7.0, Cisco Secure
Firewall** (the JSON of a Management Center's REST API and the configuration
export of a Device Manager, read; a script that loads a new policy through
the API of a Management Center and a file for the import of a Device Manager,
written). What each rests on and what nobody has checked on a device is in
the development log.

| Release | Brand | Read (expected) | Write (expected) | What will need care |
|---|---|---|---|---|
| 0.8.0 | **pfSense** (with OPNsense, its relative, where the two agree) | `config.xml`: rules per interface, floating rules, aliases, port forwards, 1:1 and outbound NAT | a `config.xml` fragment | Floating rules that are not "quick" are last match, not first, and can be for several interfaces and for outgoing traffic. Interface rules are bound to the interface traffic arrives on, like ASA access lists. Port forwards are applied before the filter, so rules name the translated address (the model's `lookup_after_dnat`), and come with linked filter rules |
| 0.9.0 | **SonicWall** (SonicOS 6.5 and 7) | the exported settings file (`.exp`, an encoded list of keys and values) or the output of the API or CLI (SonicOS 6.5 and 7 have both) | CLI commands | Access rules live in a matrix of zone pairs with a priority each. NAT policies are a separate table with original and translated source, destination and service |
| 0.10.0 | **WatchGuard** (Fireware) | the XML configuration file of Policy Manager | XML for Policy Manager | Policies are ordered automatically by precedence unless auto-order is off: the order in the file is not the order of evaluation. Proxy policies, aliases, static NAT actions, 1-to-1 and dynamic NAT |
| 0.11.0 | **Barracuda** CloudGen Firewall | the export of a forwarding ruleset with its firewall objects | the same format | To be found out first: which export exists outside Firewall Admin. NAT is part of a rule (the action Dst NAT, Map, App Redirect, and connection objects for source NAT), not a table of its own |
| 0.12.0 | **Juniper** SRX (Junos) | `show configuration \| display set`, and the same configuration in braces | `set` commands | Policies per zone pair (`from-zone ... to-zone ...`) are looked up first, global policies after them. Address books per zone and global, application sets, source, destination and static NAT rule sets. Destination and static NAT come before the policy lookup, so policies name the real address (`lookup_after_dnat`); source NAT comes after. ScreenOS is not part of this release |

Not on the list, and asked for often enough to keep in mind: nftables,
OPNsense as a target of its own, Huawei USG, Forcepoint, Stormshield,
MikroTik RouterOS, VMware NSX distributed firewall, cloud security groups
(AWS, Azure NSG).

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
7. **Hit counts** where a source exports them: allowed but never used.
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
10. Static NAT between address sets of different size is reported for ASA and
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
4. Cisco Secure Firewall, on a Management Center and an FTD device in a lab:
   fetch a policy with the calls of the manual and compare the answers with
   `fmc_sample.json` (above all: how a policy says that it inherits, whether
   the list of a child holds the rules of its parent, the fields of a
   prefilter rule); run `fmc_to_fmc` and `panos_to_fmc` with `--dry-run` and
   then for real, and check the order of the rules, the names it refuses and
   what `--undo` leaves; export a Device Manager, compare with
   `fdm_sample.txt` (the container names of NAT rules, the protocol and ICMP
   names), and import `panos_to_fdm.json`.
5. The reviewer's oracles as tests: every pre-image of a real packet through
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
