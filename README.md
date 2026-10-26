# FWShift

Multi-vendor firewall policy converter. It reads a firewall configuration,
turns it into a vendor-neutral model, and writes it out for another platform,
together with a report that says, rule by rule, what was converted exactly,
what was approximated and what a person has to look at.

| | Read | Write |
|---|---|---|
| Palo Alto PAN-OS / Panorama | XML configuration export, or `set` commands | `set` commands |
| Fortinet FortiOS | configuration backup (CLI text) | CLI configuration |
| Check Point | Management API export (JSON) | shell script of `mgmt_cli` calls |
| Cisco ASA (and the running configuration of an FTD, read only) | `show running-config` | ASA commands (9.x) |
| Cisco IOS and IOS XE (routers) | `show running-config`: interface access lists, object groups, the zone-based firewall, NAT | commands for the zone-based policy firewall |
| Huawei USG (USG6000, USG6000E, USG9500) | `display current-configuration`: security zones, address and service sets, `security-policy`, `nat server`, `nat-policy` | commands for the system view |
| Stormshield SNS (v4) | the ConfigFiles as a `.tgz` (`decbackup` of a backup): interfaces, objects, groups, the active filter slot and the global one | a script of serverd commands (`snscli --script`) |
| Cisco Meraki MX | the answers of the Dashboard API for one network in one JSON file: VLANs, static routes, policy objects, the outbound and layer 7 rules, port forwarding, 1:1 and 1:many NAT, NAT exceptions and the inbound table | a curl script that backs up and puts the outbound and NAT tables |
| Cisco Secure Firewall (FTD) managed by a Management Center (FMC) | the JSON its REST API returns | a Python script that creates a new policy through the REST API |
| Cisco Secure Firewall (FTD) managed by its Device Manager (FDM) | the configuration export (`.txt` or `.zip`), or the JSON of its REST API | a file for the configuration import |
| Sophos Firewall (SFOS 18 and later) | the export of *Import export* (`.tar` or its `Entities.xml`) | the same, for import |
| pfSense (2.6 and later; CE and Plus) | the configuration backup (`config.xml`) | the areas Aliases, NAT and Firewall Rules, for *Backup & Restore* |
| OPNsense (24.7 to 26.7) | the configuration backup (`config.xml`) | the areas Aliases, NAT and Firewall Rules of a chosen series, for *Backups* |
| SonicWall (SonicOS 6.5 and 7) | the settings export (`.exp`) | commands of the SonicOS 7 command line |
| WatchGuard (Fireware 12) | the configuration file of Policy Manager (XML) | its policy part, to merge into a configuration of the target |
| Barracuda CloudGen Firewall (8.0 and later) | the answers of its REST API (JSON) | a shell script that creates the rules through that API |
| Juniper SRX (Junos OS) | `show configuration \| display set`, or the configuration in braces | `set` commands, for `load set` |
| Linux iptables / ip6tables | `iptables-save` output | `iptables-restore` file |
| Linux nftables | `nft list ruleset` output, or its JSON (`nft -j list ruleset`) | a ruleset for `nft -f`: one table, `inet fwshift` |
| VMware NSX (distributed firewall) | the JSON of the Policy API: the hierarchical tree, or the list answers of groups, services and security policies | the body of one hierarchical `PATCH /policy/api/v1/infra` |
| AWS EC2 security groups (and network ACLs) | the JSON of the AWS CLI for one VPC: security groups, network interfaces, subnets, network ACLs, prefix lists | a shell script of AWS CLI calls that creates new security groups |
| Azure network security groups | the JSON of the Azure CLI, the REST API, an ARM template or Resource Graph: groups, network interfaces, virtual networks, service tags | an ARM template with a group per zone |
| Google Cloud firewall rules and network firewall policies | the JSON of gcloud for one VPC network: VPC firewall rules, global and regional network firewall policies, the network, the instances (hierarchical policies when added) | a shell script of gcloud commands that creates a new network firewall policy |
| Terraform (hashicorp/aws, hashicorp/azurerm, hashicorp/google) | `terraform show -json` of a state or a plan, or the raw state: the security groups and network ACLs of AWS, the network security groups of Azure, the firewall rules and network firewall policies of Google Cloud, with their members | Terraform configuration (HCL) that creates the security groups, network security groups or network firewall policy |
| MikroTik RouterOS (6 and 7) | the output of `/export` | a script for `/import`, switched on by one change |
| Forcepoint NGFW (SMC 6.10 to 7.4) | the answers of the SMC REST API for one policy, as `fwshift script forcepoint-dump` fetches them | a Python script that creates a new policy through the SMC REST API |
| Azure Firewall | the JSON of the Azure CLI, the REST API or an exported ARM template: a firewall policy with its rule collection groups and base policies, IP groups, service tags; or the classic rules of a firewall | an ARM template that creates a new firewall policy (network rule collections, DNAT rules), associated with no firewall |
| AWS Network Firewall | the JSON of the AWS CLI for one firewall policy: `describe-firewall-policy`, `describe-rule-group` for its rule groups (stateless rules, 5-tuple and Suricata rules, domain lists), the inspection VPC for `HOME_NET` | a shell script of AWS CLI calls that creates a stateful rule group and a firewall policy, associated with no firewall |
| pf (OpenBSD, FreeBSD) | `pf.conf` (macros, tables, `match`, `nat-to`/`rdr-to`, FreeBSD's `nat`/`rdr`/`binat`), or `pfctl -sr` | a ruleset for an anchor (`pfctl -a fwshift -f`), decided when traffic leaves, tagged by the zone it came from |
| VyOS 1.4 and later (read also VyOS 1.3, Vyatta and EdgeOS) | `set` commands (`show configuration commands`) or the configuration in braces (`config.boot`) | `set` commands for a configuration session: groups, named chains, zones and NAT rules |
| Juniper ScreenOS (NetScreen, SSG, ISG; 5.x and 6.x) | `get config` | — (read only) |
| Cisco PIX (6.x; 7 and later read as an ASA) | `write terminal` / `show running-config` | — (read only) |

It also **audits** a policy, of any of these formats: rules that allow too
much, rules that never match because earlier rules cover them, unused and
duplicate objects, and - from the hit counters of Check Point, PAN-OS and
FortiOS - allow rules that the counters prove unused. On its own, or before and after a
conversion. And it draws
the **zone matrix** of a policy: what each zone may reach in each other zone,
on which services, through which rules; checks a policy against a **zone and
conduit model** kept as a file (IEC 62443), as a gate for a pipeline; and
names every connection two policies decide differently - before and after a
change, or a source and its conversion read back (the **equivalence check**).
Where a FortiOS, PAN-OS or ASA configuration holds its interfaces and static
routes, FWShift reads the **networks behind each zone** from them, for the
targets that have no zones (cloud security groups and firewalls, NSX, Meraki) or keep a rule
to its zones by its addresses (ASA, pfSense), and for the equivalence check.
Findings, the matrix, the conduit check and comparisons can be written as
**SARIF** (for code scanning in a pipeline), **CSV** (for a spreadsheet or a
ticketing system) or one **HTML** page to read and sign (`--format`, and
`--report-sarif`, `--report-csv`, `--report-html` for a conversion).

Pure Python, standard library only, Python 3.9 or newer.

> **Status: alpha (0.41).** The converter is tested against synthetic
> configurations and went through several rounds of adversarial review.
>
> * **iptables** and **nftables** are checked against the real thing:
>   generated rulesets are loaded into a Linux kernel, and real packets
>   forwarded through it are compared with the model, in both directions. That
>   covers the IPv4 filter rules on one kernel (iptables 1.8.10, nf_tables
>   backend; nft 1.0.9); NAT rules and IPv6 rules are loaded but no packets
>   are sent through them. Generated nftables rulesets are also listed back
>   by nft, as text and as JSON, and both listings must give the same model.
> * **AWS, Azure and Google Cloud** output was loaded into a real account by [the lab](https://github.com/jkobierczynski/FWShift/blob/HEAD/lab/README.md),
>   for one synthetic policy: AWS security groups and Azure NSGs decided all 160 test connections between real
>   instances as the source does (or as the report announced); on Google Cloud the 32 connections inside a zone
>   differed, as announced, until 0.32.1 wrote them: then all 160 passed.
> * **FortiOS**, **PAN-OS**, **Cisco ASA**, **Juniper SRX** and **Cisco IOS XE** output was loaded on a real FortiGate-VM
>   (FortiOS 8.0.1), VM-Series (PAN-OS 11.2.15), ASAv (9.24.10), vSRX (Junos 23.4R2-S8.9) and Catalyst 8000V (IOS XE
>   26.02.1, the zone-based firewall), the AWS Marketplace images, by the lab,
>   for the same policy: all 128 connections through each as the source decides. The policy then had security rules
>   only; since 0.37.0 it has NAT as well (a hide NAT and a published web server), which the lab checks: through the
>   Linux kernel for nftables and iptables, on the FortiGate-VM, the VM-Series and the Catalyst 8000V, which passed
>   it in 0.40.17, on the ASAv in 0.40.21, on the vSRX in 0.41.0 and on pfSense Plus in 0.41.1 (every check of the addresses seen; the FortiGate
>   with central NAT; the 8000V and the ASAv with one connection blocked as announced, to the real address of the host
>   their static NAT publishes); on OPNsense at its next run. Since 0.38.0 every run of tiers
>   2 and 3 also exports the policy from the firewall afterwards, reads it with FWShift and compares it with what was
>   loaded and with the source (the read-back). Since 0.39.0 tier 3 runs on Azure as well, for the images it offers
>   (scripted from the vendors' documentation, never run there); on Google Cloud the images are found, and a run waits
>   for the firewalls' interfaces to be written its way.
> * **pfSense** and **OPNsense** output passed the same way on Netgate's pfSense Plus 26.07 and on OPNsense 26.1.5 (AWS
>   Marketplace), the areas put into each firewall's `config.xml` by the lab as a restore of each area does (not through
>   the web console's restore).
> * **SonicWall** output passed the same way on a SonicWall NSv (SonicOSX 8.2.2-8015, AWS Marketplace, pay as you go),
>   NAT included: all 129 connections and the 16 checks of the addresses seen as the source decides (0.40.15, after
>   nineteen runs that shaped the commands: `nat-policy ipv4`, every rule's place in one list of all zone pairs,
>   IPv6 rules placed by SonicOS, SonicOS's own zones and NAT policies; DEVELOPMENT.md has each step).
> * **Check Point** output passed the same way on Check Point's All-In-One (R82.20, a standalone gateway and
>   management, AWS Marketplace) in 0.40.21: FWShift's `mgmt_cli` script loaded, the policy published and installed on
>   the gateway, every connection through it as the source decides, NAT included, and the rulebase read back through
>   the Management API. It took three runs; the last changed the hide NAT (behind the outgoing interface's address,
>   towards its zone's networks).
> * **Huawei USG, Stormshield SNS, Cisco Meraki MX, Cisco Secure Firewall,
>   Sophos Firewall, WatchGuard, Barracuda, VMware NSX, RouterOS, Forcepoint, Azure Firewall, AWS Network Firewall, pf
>   and VyOS** output has **not been loaded on a device**, the **Terraform** output has not been applied with
>   Terraform, and no **ScreenOS** or **PIX** configuration (both read only) was read from a device. The Check Point input format is taken from the API
>   documentation, not from a real export, the FTD syntax from Cisco's
>   command references, and the Sophos format from the documentation of its
>   XML API and the templates of Sophos's own SDK; a few element names of a
>   Sophos NAT rule are in neither. The JSON of a Management Center and of a
>   Device Manager is taken from the API documentation and from the tooling
>   Cisco publishes for both (Ansible, Terraform, its Python client); the
>   script for a Management Center has only ever talked to a stand-in written
>   for the tests. How pfSense turns its configuration into pf rules is taken
>   from its source code (2.6, 2.7.2 and the current development branch), and
>   checked against a model of it written for the tests, not against pf; so is
>   how OPNsense does (24.7 to 26.7, from the code of each series). The
>   SonicWall settings export is undocumented beyond its encoding: its keys are
>   those the published readers of the format agree on, and the commands are
>   those of SonicWall's knowledge base, a few of them assumed. The WatchGuard
>   configuration file is not documented at all: its elements are those the
>   published readers of the format agree on. The REST API of a Barracuda
>   CloudGen Firewall is documented by examples only, and so is what FWShift
>   reads and writes of it. Junos is taken from Juniper's documentation and the
>   grammar of a published reader of it (its output now also loaded on a vSRX). The NSX Policy API is taken from
>   VMware's API reference and the schema of its Python SDK and Terraform
>   provider; AWS from the service model of the AWS CLI (botocore) and the EC2
>   documentation; Azure from Microsoft's REST API specifications, the Azure
>   CLI and the documentation; RouterOS from MikroTik's documentation, the
>   schemas of the Ansible collection and the Terraform provider for it, and
>   exports published as test data; the Forcepoint SMC API from its API guide and the
>   Python library and Terraform provider Forcepoint publishes for it (the loader and the
>   dump program have only talked to a stand-in written for the tests); Terraform from the documentation and source of its
>   JSON output and the documentation and schemas of the AWS, Azure and Google providers; Google Cloud from Google's API
>   reference and the gcloud documentation, and its scripts were run against a project only by the lab; IOS from Cisco's configuration
>   guides, command references and IOS XE YANG models, and loaded on one router (a Catalyst 8000V, IOS XE 26.02.1); Huawei USG from Huawei's
>   documentation and support pages (its command reference could not be read), and nothing was loaded on a firewall;
>   Stormshield from its command reference and, for the configuration files (whose rule syntax is not published), from
>   its own tools and their test data, and nothing was run on a firewall; Meraki from the OpenAPI specification of the
>   Dashboard API, Meraki's documentation and the SDK, Terraform provider and Ansible modules Cisco publishes, and no
>   call was made to a Dashboard; Azure Firewall from Microsoft's documentation and the ARM template reference (a few
>   limits from memory), and nothing was deployed to a subscription; AWS Network Firewall from its developer guide and
>   API reference and Suricata's documentation, and no call was made to AWS; pf from pf.conf(5) of OpenBSD and
>   FreeBSD and OpenBSD's PF FAQ, and nothing was loaded with pfctl; VyOS from its documentation and the source of
>   vyos-1x (the nftables templates, the CLI definitions and the migration scripts that take 1.3 configurations to
>   1.4), VyOS 1.3, Vyatta and EdgeOS as that migration rewrites them, EdgeOS NAT from Ubiquiti's articles, and
>   nothing was loaded on a router; ScreenOS from what could be read of Juniper's documentation, published `get config`
>   excerpts and community pages, much of it assumed; PIX 6.x from Cisco's PIX command reference 6.3 and its NAT
>   documents. None of these inputs is a real export.
>   Several conversion rules rest on
>   vendor behaviour taken from documentation rather than from a lab.
>
> Treat the output as a draft for a lab, read the report, and never load it in
> production unreviewed.

## Using it safely

1. **Work on a trusted workstation; treat exports, outputs and reports as confidential (they map your network).**
2. **Convert with `--strict` and read the whole report: every *needs review* and *approximated* line, every disabled rule.**
3. **Prove the result: the equivalence check (`--compare`, or `fwshift compare` on the output read back); accept each difference explicitly.**
4. **Treat every output as privileged code: read it before running it, and run loaders with `--show` and `--dry-run` first.**
5. **Load into a lab or a new, unassigned policy first; outputs that act when loaded (iptables, nft, restored areas) only with console access.**
6. **Give keys and passwords through the environment or the prompt, to a least-privilege API account; never use `--insecure`.**
7. **Keep the journal of a loader run until the change is accepted: `--undo` removes exactly what that run created.**
8. **After loading, read the policy back from the target, compare it again, and test the critical flows on the device.**
9. **Install from PyPI (`pip install fwshift`) or only release packages whose checksums match `SHA256SUMS`; publish, install or deploy on the target yourself.**

The reasons, and what an outside security review found, are in [docs/security/SECURITY_REVIEW.md](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/security/SECURITY_REVIEW.md).

## Documentation

* **[User manual](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/MANUAL.md)**: getting a configuration out of the
  source firewall, every command and option, how to read the report, a
  reference of all findings, how each difference between the platforms is
  handled, and how to load the result.
* **[Field guide](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/guide.html)**: every feature on one page, with real
  commands and output, and per brand what to export, how to load the result
  and the edge cases to watch for. Open it in a browser.
* **[DEVELOPMENT.md](https://github.com/jkobierczynski/FWShift/blob/HEAD/DEVELOPMENT.md)**: architecture, the rules the code
  follows, how to add a vendor, testing, and the development log.
* **[TODO.md](https://github.com/jkobierczynski/FWShift/blob/HEAD/TODO.md)**: what is planned, release by release.
* **[The lab](https://github.com/jkobierczynski/FWShift/blob/HEAD/lab/README.md)**: scripts that put a converted policy on a real target (AWS, Azure
  and Google Cloud networks; nftables, iptables, RouterOS, OPNsense and pfSense on your own Linux host; firewall
  images of the AWS Marketplace) and check it with real connections.
* **[Security review](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/security/SECURITY_REVIEW.md)**: an outside review of the project (by ChatGPT, October 2026), and what
  was done about each point.

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
pip install fwshift      # from PyPI; or "pipx install fwshift"
fwshift --version
```

From the source tree: `pip install .` (or `pip install -e ".[dev]"` for development); without installing,
`PYTHONPATH=src python3 -m fwshift ...`. The package on PyPI is uploaded by the release workflow of the repository
(trusted publishing, no stored token), from the same build as the release packages.

Each version tag has a release with packages: `fwshift-X.Y.Z.zip`, the
project as tagged; a wheel for `pip install`; and `fwshift-X.Y.Z.pyz`, one
file that needs nothing but Python 3.9 or newer:

```sh
python3 fwshift-0.41.2.pyz --version
python3 fwshift-0.41.2.pyz convert running-config.xml --to fortios -o fortigate.conf
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

# nftables, both ways: the ruleset as nft lists it, and one table for nft -f
nft list ruleset > ruleset.nft
fwshift convert ruleset.nft --to panos -o panos.set --report report.txt --zone-map eth0=untrust --zone-map eth1=trust
fwshift convert running-config.xml --to nftables -o fwshift.nft --zone-map trust=eth1 --zone-map untrust=eth0
nft -c -f fwshift.nft && nft -f fwshift.nft

# iptables to Check Point: a script of mgmt_cli calls that publishes nothing
fwshift convert rules.v4 --to checkpoint -o checkpoint.sh --report report.txt --target-prefix mig_

# Cisco ASA to PAN-OS: interface names become zones
fwshift convert asa-running.cfg --to panos -o panos.set --report report.txt \
    --interface-map GigabitEthernet0/0=ethernet1/1

# Cisco Meraki MX (the bundle of Dashboard answers, MANUAL section 3) to
# PAN-OS; to Meraki, a curl script (DRY_RUN=1 writes the bodies only) with the
# zones of the LAN and their networks
fwshift convert meraki-N_1.json --to panos -o candidate.set --report report.txt
fwshift convert candidate.xml --to meraki -o meraki.sh --report report.txt \
    --inside-zone trust --zone-network trust=10.10.0.0/16 --zone-network untrust=0.0.0.0/0,::/0

# Stormshield SNS (the .tgz decbackup makes of a backup) to FortiOS; to
# Stormshield, a script for snscli that writes one filter slot, not made active
fwshift convert backup.tgz --to fortios -o fortigate.conf --report report.txt
fwshift convert candidate.xml --to stormshield -o sns.script --report report.txt \
    --zone-map trust=in --zone-map untrust=out --target-policy 7

# Huawei USG to PAN-OS: nat server is done before the security policy, so the
# rules are rewritten for the address as it arrives; to Huawei, the output is
# commands for the system view, the zones' interfaces as comments
fwshift convert usg-current.cfg --to panos -o candidate.set --report report.txt
fwshift convert candidate.xml --to huawei -o usg.txt --report report.txt \
    --interface-map ethernet1/1=GigabitEthernet1/0/1

# Cisco IOS router to FortiOS: the interface lists, the zone-based firewall
# and NAT, composed for each pair of zones. To IOS, the output is the
# zone-based firewall; the zone-member lines are comments to move into place
fwshift convert router-running.cfg --to fortios -o fortigate.conf --report report.txt
fwshift convert fgt-backup.conf --to ios -o zbfw.cfg --report report.txt \
    --interface-map port1=GigabitEthernet0/0/0 --interface-map port2=GigabitEthernet0/0/1

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

# OPNsense: config.xml from System > Configuration > Backups, of 24.7 to 26.7.
# To an OPNsense, the output is for one series (--target-version, 26.7 by
# default) and is restored once per area; it REPLACES what the firewall has there
fwshift convert opnsense.xml --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to opnsense --target-version 26.1 -o restore.xml --report report.txt \
    --zone-map trust=lan --zone-map untrust=wan \
    --zone-network lan=10.10.0.0/16 --zone-network wan=0.0.0.0/0,::/0

# Forcepoint NGFW: write the read-only dump program, let it fetch one policy
# from the SMC REST API, and convert that. To a Forcepoint, the output is a
# program that creates a new policy on a template; it installs nothing
fwshift script forcepoint-dump -o smc_dump.py
SMC_API_KEY=... python3 smc_dump.py --host smc.example.com --policy "Branch Policy" -o branch.json
fwshift convert branch.json --to asa -o asa.cfg --report report.txt
fwshift convert running-config.xml --to forcepoint -o load_smc.py --report report.txt
python3 load_smc.py --show

# Google Cloud: the answers of gcloud for one VPC network in one JSON object
# (section 3 of the manual). To Google Cloud, the output is a gcloud script that
# creates a new network firewall policy, associated with no network
fwshift convert gcp.json --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to gcp -o policy.sh --report report.txt \
    --zone-network trust=10.10.0.0/16 --zone-network untrust=0.0.0.0/0,::/0
DRY_RUN=1 sh policy.sh

# Terraform: what Terraform knows of the security groups (AWS), network
# security groups (Azure) or firewall rules (Google Cloud), from a state or a
# plan. To Terraform, the output is configuration that creates new groups or a
# new policy, attached to nothing
terraform show -json > state.json
fwshift convert state.json --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to terraform-aws -o groups.tf --report report.txt \
    --zone-network trust=10.10.0.0/16 --zone-network untrust=0.0.0.0/0,::/0 --inside-zone trust

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

# VMware NSX: the hierarchical Policy API answer is the input. To NSX, the
# output is the body of one PATCH; the distributed firewall has no zones, so
# give the networks behind them
curl -sS -u admin 'https://MANAGER/policy/api/v1/infra?type_filter=Domain;Group;SecurityPolicy;Rule;Service;ServiceEntry;Segment' > nsx.json
fwshift convert nsx.json --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to nsx -o nsx-body.json --report report.txt --target-prefix mig- \
    --zone-network trust=10.10.0.0/16 --zone-network untrust=0.0.0.0/0,::/0

# AWS security groups: the answers of the AWS CLI for one VPC, in one JSON array
# (section 3 of the manual). To AWS, the output is a script that creates new
# groups without members, and says which addresses each one is for
fwshift convert aws.json --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to aws -o groups.sh --report report.txt \
    --zone-network trust=10.10.0.0/16 --zone-network dmz=10.20.0.0/24 --zone-network untrust=0.0.0.0/0,::/0 \
    --inside-zone dmz
DRY_RUN=1 sh groups.sh

# Azure network security groups: the answers of the Azure CLI in one JSON array
# (section 3 of the manual). To Azure, the output is an ARM template with a group
# per zone, to associate with the subnets of that zone
fwshift convert azure.json --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to azure -o nsgs.json --report report.txt \
    --zone-network trust=10.10.0.0/16 --zone-network dmz=10.20.0.0/24 --zone-network untrust=0.0.0.0/0,::/0 \
    --inside-zone dmz
az deployment group what-if -g rg-net --template-file nsgs.json

# MikroTik RouterOS: the output of /export. To RouterOS, the output is a script
# for /import whose rules change nothing until the jumps at its end are enabled
fwshift convert router.rsc --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to routeros -o fwshift.rsc --report report.txt \
    --interface-map ethernet1/1=ether1 --interface-map ethernet1/2=bridge

# Azure Firewall: the answers of the Azure CLI for a firewall policy, its base
# policy and their rule collection groups, in one JSON array (section 3 of the
# manual). To Azure Firewall, the output is an ARM template that creates a new
# policy, associated with no firewall
fwshift convert azurefw.json --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to azure-firewall -o fwpolicy.json --report report.txt \
    --zone-network trust=10.10.0.0/16 --zone-network dmz=10.20.0.0/24 --zone-network untrust=0.0.0.0/0
az deployment group what-if -g rg-hub --template-file fwpolicy.json

# AWS Network Firewall: the answers of the AWS CLI for one firewall policy and its
# rule groups, one after the other in one file (section 3 of the manual). To AWS
# Network Firewall, the output is a script that creates a new policy and its rule
# group, associated with no firewall
fwshift convert nfw.json --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to aws-network-firewall -o nfw.sh --report report.txt \
    --zone-network trust=10.10.0.0/16 --zone-network untrust=0.0.0.0/0,::/0
DRY_RUN=1 sh nfw.sh

# pf: pf.conf of OpenBSD (FreeBSD's nat, rdr and binat too); addresses of
# interfaces are not in it: give them. To pf, a ruleset for the anchor
# "fwshift", for OpenBSD or FreeBSD 15 and later
fwshift convert pf.conf --to panos -o panos.set --report report.txt \
    --interface-address em1=10.0.1.1/24
fwshift convert running-config.xml --to pf -o fwshift.conf --report report.txt \
    --zone-map trust=em1 --zone-map untrust=em0
pfctl -vnf fwshift.conf -a fwshift && pfctl -a fwshift -f fwshift.conf

# VyOS 1.4 and later, VyOS 1.3 and EdgeOS: show configuration commands, or config.boot.
# To VyOS, set commands to paste into a configuration session, then commit-confirm
fwshift convert config.boot --to fortios -o fortigate.conf --report report.txt
fwshift convert running-config.xml --to vyos -o fwshift.txt --report report.txt \
    --interface-map ethernet1/1=eth0 --interface-map ethernet1/2=eth1

# Juniper ScreenOS and Cisco PIX 6.x, read only: get config of a NetScreen or
# SSG, write terminal of a PIX (PIX 7 and later are read as an ASA)
fwshift convert ssg.conf --to junos -o srx.set --report report.txt
fwshift convert pix.cfg --to asa -o asa.cfg --report report.txt

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

# Does the policy keep to the zone and conduit model? Exit status 3 when not.
# A first model can be drafted from what the policy allows today.
fwshift conduits running-config.xml --model plant.json
fwshift conduits running-config.xml --draft plant.json --network-zone office@trust=10.10.0.0/16 ...

# Which connections did a change open or close? And a conversion?
fwshift compare before.xml after.xml
fwshift convert running-config.xml --to iptables -o rules.v4 --report report.txt --compare compare.txt \
    --zone-network trust=10.10.0.0/16 --zone-network untrust=0.0.0.0/0,::/0
```

The [manual](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/MANUAL.md#3-getting-the-source-configuration) shows how to
get the input for each platform; for Check Point that is three `mgmt_cli show`
calls, for an ASA or an IOS router `show running-config`, for a Huawei USG `display current-configuration`, for a Stormshield firewall its backup opened with `decbackup`, for a Meraki MX the answers of the Dashboard API in one file, for a Sophos Firewall an export under
*Backup & firmware > Import export*, for a Management Center a handful of
`curl` calls to its REST API, for a Device Manager its configuration export,
for a pfSense the backup under *Diagnostics > Backup & Restore*, for an
OPNsense the one under *System > Configuration > Backups*, for a
SonicWall *Export Settings*, for a WatchGuard the file Policy Manager saves,
for a Barracuda a few `curl` calls to its REST API, for an SRX
`show configuration | display inheritance no-comments | display set`, for a
Forcepoint the program `fwshift script forcepoint-dump` writes, for Google Cloud
a few `gcloud ... --format=json` answers, for Terraform `terraform show -json`,
for Azure Firewall a few `az network firewall policy` answers, for AWS Network
Firewall the answers of `aws network-firewall describe-firewall-policy` and
`describe-rule-group`, for pf its `pf.conf`, for VyOS or EdgeOS `show
configuration commands`, for ScreenOS `get config`, for a PIX `write terminal`.

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
| Use | allow rules that the hit counters prove unused (a Check Point rulebase exported with hits, or `--hits` with the answer of PAN-OS or FortiOS) or the logs (`--usage-store`, below); objects and services of a used rule that no connection used; rules about whose use neither proves anything |
| After a conversion | a blocking rule the target could not take, with what now allows its traffic (the rules below it, or a default) |

Each check can be switched off, accepted (for all rules, or for one rule
with a reason), or acted on in a conversion: `disable` the rules, or
`reorder` shadowed ones. A rule is only called dead when that is proven from
zones, addresses and ports against all earlier rules together, and disabling
such a rule changes no verdict; the tests check that against every packet of
a small world. A rule that was read only approximately is not called dead and
proves nothing about another rule: the audit lists it instead.
`--audit-fail-on high` makes it a gate for a pipeline. See
[section 13 of the manual](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/MANUAL.md#13-auditing-a-policy).

## Rule usage

`fwshift usage` reads the logs of a Check Point firewall (what Log Exporter
sends, or the answer of `show-logs`), the traffic logs of PAN-OS and FortiOS,
or the lines of the `LOG` rules of an iptables firewall (the `log` statements
of nftables write the same lines), and says which rules,
objects and services they show used, into a store that grows with every run,
over a window of days. Check Point, PAN-OS and FortiOS logs name the rule the
firewall chose (by its UUID where they can); an iptables or nftables line names none, and
is matched against the rules of the policy: certain where the first rule it
meets surely matches it, possible where it only might.

```
$ fwshift usage checkpoint.json --logs gw-edge.log --store usage.db --html usage.html
  ...
  [medium] UNUSED_RULE: rule 'DMZ users' allows traffic from any zone to any zone, and the logs of gw-edge show no connection that the gateway attributed to it from 2026-07-03 to 2026-09-30, with logs on every day
  [low] UNUSED_RULE_OBJECT: rule 'DNS' of its sources 'dmz-net' had no connection from 2026-07-03 to 2026-09-30, out of 96 connection(s) through the rule
```

An allow rule whose connections used a small part of what it allows gets
`WIDER_THAN_TRAFFIC` with a narrower rule: its addresses and services cut down
to what was used, never wider than the rule (`--propose FILE` writes them for
review).

A rule is only called unused when the logs can prove it: the rule logs, every
gateway it is on sent logs on every day of the window, no line of them could
not be read, and the rule did not change within it (iptables, nftables, PAN-OS and
FortiOS configurations do not say when it changed: `--unchanged-since` is your
word for it, or for PAN-OS the hit counters). A rule with only
possible connections is never called unused. Otherwise it says why they prove
nothing. See
[section 15 of the manual](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/MANUAL.md#15-rule-usage-from-logs).

Synthetic configurations to try it on, one per format, are in
[`tests/data`](https://github.com/jkobierczynski/FWShift/tree/HEAD/tests/data), with their conversions in
[`tests/data/expected`](https://github.com/jkobierczynski/FWShift/tree/HEAD/tests/data/expected).

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
[section 14 of the manual](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/MANUAL.md#14-the-zone-matrix).

## Zone and conduit model, and the equivalence check

The model of which zone may reach which, on which services, is a JSON file
next to the firewall: zones (networks, the zones of the policy they lie
behind, a target security level) and conduits (from, to, services).
`fwshift conduits` checks the matrix of a policy against it: what the policy
allows beyond a conduit, between zones without one, inside a zone beyond what
it may, or to addresses in no zone, and the conduits the policy keeps closed.
A finding that rests on what cannot be read exactly is said to be possible,
and fails the gate too. See [section 16](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/MANUAL.md#16-the-zone-and-conduit-model).

`fwshift compare` reads two configurations, of any formats, and names every
connection whose verdict differs, per pair of zones: opened or closed, for
certain or possibly, with the rule that decides it in each. Applications,
users, URL categories and schedules are compared as labels of a connection;
objects and rules both hold alike but that cannot be read decide alike.
`fwshift convert --compare` reads the output back (for the seventeen targets
FWShift reads back) and does the same for the conversion. See
[section 17](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/MANUAL.md#17-the-equivalence-check).

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

| | Check Point | iptables | nftables |
|---|---|---|---|
| Address objects | host, network, address range, DNS domain; gateways by their main address | none: addresses are written into the rules | none: addresses in the rules, or in sets |
| Address groups | group, nested | read: none. Written: one chain per list | named sets of addresses. Written: anonymous sets in the rules |
| Services | TCP, UDP, SCTP with source ports, ICMP, ICMPv6, IP protocol | protocol, port lists, ICMP type and code | the same, `th` ports with a protocol set, port comparisons |
| Service groups | yes | none | none |
| Security rules | one ordered layer with its inline layers flattened; zones in cells, negation, action, track, disabled, install-on reported | `FORWARD` chain with the chains it jumps to flattened; interfaces as zones, negation, connection state | every base chain at the forward hook (ip, ip6, inet tables), combined as the kernel runs them; jump, goto, return, verdict maps, concatenations flattened; interfaces as zones, negation, connection state, logging |
| NAT | manual and automatic rules: hide, static, port translation, no-NAT | `DNAT`, `SNAT`, `MASQUERADE` and exemptions of the `nat` table (IPv4) | `dnat`, `snat`, `masquerade`, NAT maps and exemptions at prerouting and postrouting (IPv4) |
| Scope | one access layer and the NAT rulebase of one policy package | one IP version per file | both IP versions in one table |

| | Cisco Meraki MX |
|---|---|
| Address objects | addresses and networks, `VLAN(n).*` and `VLAN(n).k`, policy objects (CIDR, IP and mask, FQDN), host names as destinations; a zone per VLAN with its static routes. Written: addresses and networks in the rules |
| Address groups | policy object groups. Written: their addresses |
| Services | TCP, UDP, ICMP, ICMPv6 and any, with a list of ports or one range. Written: one rule per protocol and range |
| Security rules | the outbound table, first match, ending in the fixed allow; layer 7 rules of ports and address ranges; the inbound table with NAT exceptions or in passthrough mode. Written: the outbound table, with a final deny where the source blocks the rest |
| NAT | port forwarding, 1:1 and 1:many NAT with their allowed remote addresses, NAT to the uplink. Written: the same, with the rules that allow all of a NAT rule's traffic as its allowed remote addresses |
| Scope | one network; group policies, the cellular and VPN tables and the inbound table as a target left out |

| | Stormshield SNS |
|---|---|
| Address objects | hosts (address, range, IPv4 and IPv6), networks, FQDN objects, `Network_<if>`, `Firewall_<if>`, `firewall_all`, `Network_internals`, `Internet`. Written: hosts and networks |
| Address groups | `objectgroup`, nested. Written: groups |
| Services | services (a port or a range, TCP, UDP or both), service groups, protocols, the predefined services by their ports. Written: services and protocols |
| Security rules | the active filter slot after the global one, first match, with interfaces (`on`), negation, users (carried), ports and `ipproto`; `decrypt` and `log` left out. Written: one filter slot, a rule per interface pair and kind of service, disabled rules `state=off` |
| NAT | not read (the syntax of the slot file is not published). Written: source NAT to an interface, a pool or a static address, static both ways, destination NAT |
| Scope | one firewall; the implicit rules, and making the slot active, left to you |

| | Huawei USG |
|---|---|
| Address objects | entries of address sets (mask, mask length, wildcard, range, IPv6) and the addresses of a rule. Written: address sets, one address in the rule |
| Address groups | nested address sets |
| Services | service sets (TCP, UDP, SCTP with source and destination ports, ICMP types, protocols), nested; the predefined services by their well-known ports; a service written in a rule. Written: service sets |
| Security rules | `security-policy`, first match, with zones, addresses, exclusions, services, `disable` and logging; the defaults (`default action`, permit inside a zone). Written: the same, with zones listed, rules it cannot say disabled, defaults as rules or `default action permit` |
| NAT | `nat server` (before the policy: ports, protocol, static), `nat-policy` (easy-ip, address pools, no-nat). Written: the same forms |
| Scope | the root system of one firewall; the zones' interfaces and the order among existing rules left to you |

| | Cisco IOS and IOS XE |
|---|---|
| Address objects | addresses and wildcard masks of an entry (non-contiguous ones as the ranges they stand for), IPv6 prefixes, the addresses of the interfaces. Written: object groups (IPv4), prefixes (IPv6) |
| Address groups | `object-group network` and `v6-network`, nested; host names are not resolved |
| Services | protocols by name and number, ports with `eq` (several), `neq`, `lt`, `gt`, `range` and the port names of each protocol, ICMP and ICMPv6 names and numbers, `object-group service`. Written: the entries of a list |
| Security rules | the lists bound in and out to each interface (numbered, named, standard, extended, IPv6) in sequence order with their implicit deny; the zone-based firewall (zone pairs, inspect policies, class maps with access lists, `match protocol` as ports, `class-default`, the zone rules of IOS); composed for each pair of zones where more than the inbound list decides. Written: a zone per zone, an access list and class map per rule, an inspect policy per zone pair |
| NAT | `ip nat inside source` static (address, network, port) and dynamic (a list of sources to an interface or a pool). Written as comments: the same forms |
| Scope | one router, forwarded traffic; the zone membership and NAT left to you |

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

| | OPNsense |
|---|---|
| Address objects | aliases of the newer model (addresses, networks, ranges, host names, entries with `!` that leave addresses out, worked out as the pf table), the networks and addresses of interfaces, *This Firewall* |
| Address groups | aliases, nested; disabled aliases as the empty tables they are; a rule for one IP version takes the addresses of that version |
| Services | protocol and ports of a rule (ports for TCP and UDP only), port aliases (nested), ICMP types by name and ICMPv6 types by number |
| Security rules | both kinds: those of *Rules* and of *Rules [new]*, in the order of OPNsense's priorities (floating, groups by their sequence, interfaces; the newer kind first in each; the rules port forwards register last); quick and not on every tab, in, out and both; *received-on*; flags as each series reads them. Written: rules of *Rules [new]* for the series given |
| NAT | port forwards in both forms (with *Pass* and *Register rule*), Source NAT rules and manual outbound rules in every mode, automatic outbound NAT, 1:1 NAT both ways and one way |
| Scope | the whole configuration, OPNsense 24.7 to 26.7. Written for one of them (`--target-version`) |

| | Forcepoint NGFW |
|---|---|
| Address objects | hosts and routers (with their other addresses), networks (without network and broadcast address in a rule cell where *broadcast* is off), ranges, domain names, expressions (union, intersection, the exclusion of one element) |
| Address groups | groups, nested; a rule takes the part of a group of its IP version |
| Services | TCP and UDP (destination and source ports), ICMP and ICMPv6 types and codes, IP protocols, service groups; network applications and URL categories by name |
| Security rules | the IPv4 and IPv6 lists of the policy and its templates in the order of the insert points; sections; zones and match expressions; Allow, Discard, Refuse; Continue (its logging); jumps to sub-policies, flattened; NONE cells; disabled rules. Written: zones, match expressions and expressions for negation, into the list of each IP version a rule can match |
| NAT | static destination NAT (with ports), static and dynamic source NAT, `$$ Default NAT Address`, rules without translation. Written the same, used on every engine |
| Scope | one firewall policy with its templates and the sub-policies its rules jump to. Written as a new policy on a template (`--target-template`) |

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

| | VMware NSX (distributed firewall) |
|---|---|
| Address objects | addresses, networks and ranges of a group (`IPAddressExpression`), literals of a rule; segments as their subnets. Written: groups of addresses, per IP version |
| Address groups | groups, nested by path; AND and OR of their expressions; groups NSX fills itself (tags, names, virtual machines) kept as dynamic groups, written again only to NSX |
| Services | L4 port sets with source ports, ICMP and ICMPv6 type and code, IP protocols, IGMP, ALGs as their ports, nested services; the system services by their id. Written: services of at most 15 ports per entry |
| Service groups | nested services |
| Security rules | security policies in the order of their categories (Ethernet, Emergency, Infrastructure, Environment, Application), sequence numbers, jump to Application, the default layer-3 rule; allow, drop, reject; exclusions; direction, IP version, applied-to read as far as they decide; disabled; logging. Written: one policy of category Application, rules in the order of the model, zones as the networks behind them |
| NAT | not read (it is on the gateways); not written, the rules name the addresses NAT translates to |
| Scope | domain `default` of the distributed firewall. Written: services, groups and one security policy, in one `PATCH` |

| | AWS security groups |
|---|---|
| Address objects | address blocks of a rule (IPv4, IPv6), the private addresses of the network interfaces; public and Elastic IPs as static NAT. Written: address blocks in the rules |
| Address groups | a security group as the addresses of the interfaces that carry it; managed prefix lists with their entries; groups of other VPCs and accounts kept as dynamic groups |
| Services | every protocol, TCP and UDP port ranges, ICMP and ICMPv6 type and code, IP protocols. Written: the same, one per rule |
| Security rules | inbound rules; outbound rules for outside the VPC; inside, an outbound rule of the source's groups and an inbound rule of the destination's together; network ACLs as blocking rules, in rule-number order, between subnets. Written: what each rule allows without what the blocking rules above it block, on both ends, in groups cut by address |
| NAT | public and Elastic IPs of instances, read as static NAT. Not written (the internet and NAT gateways do it) |
| Scope | one VPC. Written: new groups and their rules, attached to nothing |

| | Azure network security groups |
|---|---|
| Address objects | address prefixes of a rule (IPv4, IPv6), the private addresses of the network interfaces, the subnets behind each group. Written: address prefixes in the rules |
| Address groups | service tags with the addresses of the service tag list, `AzureLoadBalancer` as 168.63.129.16, application security groups as the addresses of the interfaces that carry them; else dynamic groups, written again only to Azure |
| Services | `*` (TCP, UDP, ICMP), TCP and UDP with destination and source ports, ICMP, ESP, AH. Written: the same, one protocol per rule |
| Security rules | inbound and outbound rules in the order of their priorities, the default rules; between two groups, the outbound rules of the one and the inbound rules of the other together; allow and deny. Written: per group, the rules for traffic from and into its zone, kept to the networks of the other zone, and the default of the source |
| NAT | none (a group does no NAT). Not written: the rules are for what a group sees |
| Scope | the groups in the export, of any resource group; templates with parameters, variables, copy loops and conditions worked out. Written: an ARM template, associated with nothing |

| | Google Cloud |
|---|---|
| Address objects | source and destination ranges (IPv4, IPv6), the internal addresses and alias ranges of the instances; external addresses as static NAT. Written: ranges in the rules |
| Address groups | network tags and service accounts as the addresses of the instances that carry them (targets) or their primary addresses (sources); secure tags, address groups, host names, region codes and threat lists are not converted |
| Services | every protocol, TCP, UDP and SCTP ports, ICMP, ICMPv6, IP protocols by number. Written: the same; ICMP types and source ports cannot be |
| Security rules | the steps in Google Cloud's order: hierarchical policies (when added), VPC firewall rules (deny before allow at one priority), the global and the regional network firewall policy, `goto_next`, the implied rules; between instances, the egress rules of one and the ingress rules of the other together. Written: one global policy, each rule per IP version for ingress and egress, ending in the default of the source |
| NAT | external addresses of instances, read as static NAT. Not written (Google Cloud does it) |
| Scope | one VPC network. Written: a new policy, associated with nothing |

| | Terraform |
|---|---|
| Address objects, groups, services, rules | what the AWS, the Azure and the Google Cloud columns say, from the resources of a state or a plan: groups with their inline rules and separate rule resources (each rule once), network ACLs with their entries and associations, interfaces, instances and Elastic IPs as the members, prefix lists, subnets, VPCs; network security groups with their rules and associations, application security groups, interfaces, subnets, virtual networks and peerings; VPC firewall rules, global and regional network firewall policies with their rules and associations, networks and instances |
| Plans | read as after the apply: ids not known yet stand for the resources the configuration refers to; what is deleted is not read; what is not known is not converted |
| NAT | public addresses of instances and Elastic IPs, read as static NAT. Not written |
| Scope | one state or plan (one VPC of it for AWS, one network for Google Cloud). Written: plain HCL for hashicorp/aws (`aws_security_group`, `aws_vpc_security_group_ingress_rule` and `_egress_rule`), hashicorp/azurerm (`azurerm_network_security_group`) or hashicorp/google (`google_compute_network_firewall_policy` and its `_rule` resources), attached to nothing |

| | MikroTik RouterOS |
|---|---|
| Address objects | addresses, prefixes and IPv4 ranges of a rule; the entries of address lists, host names included. Written: in the rule, or address lists |
| Address groups | address lists (IPv4 and IPv6 apart); lists the router fills while it runs are not known |
| Services | protocols by name and number, destination and source ports (`port` either), ICMP and ICMPv6 type and code, negation. Written: one protocol per rule |
| Security rules | the `forward` chains of `/ip` and `/ipv6`, custom chains flattened (a return taken away exactly where addresses, protocols or ports say it), the default accept; accept, drop, reject, tarpit; `!dstnat` port-forward exceptions; disabled; logging. Written: chain `fwshift-forward`, zones as interface lists, the defaults at its end |
| NAT | `dst-nat`, `netmap`, `masquerade`, `src-nat`, `same`, no-NAT; the forward chain looked up after destination NAT, brought back to the original destination. Written: chains `fwshift-dstnat` and `fwshift-srcnat`, IPv4 |
| Scope | one router. Written: a script for `/import` with disabled jumps from the built-in chains |

| | Azure Firewall |
|---|---|
| Address objects | addresses, CIDRs, ranges and `*` of a rule (IPv4); FQDNs of network rules as host names. Written: CIDRs in the rules, IPv4 only |
| Address groups | IP groups and service tags with their addresses where the input holds them; else dynamic groups, written again only to Azure Firewall |
| Services | TCP, UDP, ICMP and `Any`, destination ports (`Any` with every port is every IP protocol). Written: a network rule per set of protocols and ports |
| Security rules | DNAT, network and application rules in Azure's three passes, the base policy's groups first, groups and collections by priority; what a DNAT rule translates allowed ahead of every other rule; application rules kept and not converted; the classic rules of a firewall. Written: a network rule collection per rule of the model, in order, zones as the networks behind them, the default deny or a last collection that allows |
| NAT | DNAT rules (TCP, UDP). Written: a DNAT rule per address and port, only where the model allows all it translates; source NAT is Azure's own and not written |
| Scope | one policy with its base policy, or the classic rules of one firewall. Written: an ARM template for a new policy, associated with no firewall |

| | AWS Network Firewall |
|---|---|
| Address objects | CIDR blocks and lists with negation, variables of the policy and the rule group, `HOME_NET` from the policy or the inspection VPC, `EXTERNAL_NET` as its negation. Written: in the rules, or IP set variables |
| Address groups | IP set variables; IP set references to prefix lists, with their entries; resource groups not converted |
| Services | `ip`, `tcp`, `udp` and `icmp` (ICMP and ICMPv6) with ports, port variables, `ip_proto`, `itype`, `icode`; application protocols as applications. Written: a rule per protocol, applications as their ports |
| Security rules | stateless rules per packet, with what the replies meet worked out; stateful 5-tuple rules, Suricata rules and domain lists, in action order or strict order, for each moment a flow can be decided, ended where the default action decides. Written: one stateful rule group in strict order, every rule with `flow:to_server`, zones as networks, the default of the source |
| NAT | none (Network Firewall does no NAT). Not written: the rules are for the private addresses it sees |
| Scope | one firewall policy and its rule groups. Written: a script that creates a rule group and a policy, associated with no firewall |

| | pf |
|---|---|
| Address objects | addresses, networks, ranges and host names of a rule, macros, `self` and the addresses of interfaces (from `--interface-address`). Written: in the rules, or tables `<fws_...>` |
| Address groups | tables with entries in braces and `!` entries (the most specific entry decides), lists; tables from files or filled at run time are not known. Written: tables |
| Services | protocols by name and number, ports with every operator of pf and service names, ICMP and ICMPv6 types and codes. Written: the same; a negated service by a tag of its own |
| Security rules | filter rules, last match with `quick` turned into first match; rules for arriving traffic as rules of the source zone, blocks of leaving traffic as rules of the destination zone; interfaces and interface groups as zones; `antispoof`, `set skip on`, `set block-policy`. Written: arriving traffic tagged by its zone, the rules decided when it leaves, in the order of the model |
| NAT | `nat-to`, `rdr-to` and `binat-to` on match and pass rules; FreeBSD's `nat`, `rdr`, `binat`, `no nat`, `rdr pass`. Written: `pass in quick ... rdr-to` and `match out ... nat-to` |
| Scope | one `pf.conf` (or `pfctl -sr`), without its anchors and included files. Written: a ruleset for the anchor `fwshift`, for OpenBSD and FreeBSD 15 and later |

| | VyOS |
|---|---|
| Address objects | addresses, networks and ranges of a rule; `fqdn`. Written: in the rule, or groups |
| Address groups | `address-group`, `network-group` and their `ipv6-` forms with `include`; `domain-group` as host names; `interface-group`. Written: a group for a side of several addresses |
| Services | `tcp`, `udp`, `tcp_udp` and other protocols, ports and `port-group`, ICMP and ICMPv6 types by name. Written: a rule per protocol (TCP and UDP with the same ports share one); a negated service as a chain of its own |
| Security rules | the forward filter and the named chains it jumps to (`return`, defaults), the zone-based firewall as a second chain at the forward hook; the rule-sets on interfaces and `zone-policy` of VyOS 1.3, Vyatta and EdgeOS as VyOS's migration to 1.4 rewrites them. Written: zones with a chain per pair of zones and `FWS-NO-ZONE`, or one chain `FWS-FORWARD` jumped to from the forward filter |
| NAT | `nat destination` and `nat source` (`exclude`, masquerade, addresses, ranges, networks); EdgeOS `service nat`. Written: `nat destination` and `nat source` rules from 10000, IPv4 |
| Scope | forwarded traffic of one router. Written: set commands for VyOS 1.4 and later that add and delete nothing |

| | Juniper ScreenOS (read only) |
|---|---|
| Address objects | address books per zone with the Global book behind them: addresses (IPv4, IPv6), host names; `MIP(A)` and `VIP(A)` as objects |
| Address groups | address groups of a zone's book |
| Services | custom services (TCP and UDP ports with source ports, ICMP type and code, IP protocols), service groups, the predefined services of FWShift's table |
| Security rules | policies per pair of zones, first match, then the global policies, then the default policy; negation; disabled policies; zones that do not block traffic inside them; `move`, `top` and `before` carried out |
| NAT | policy-based NAT (DIP pools, `nat dst`), MIPs, VIPs and interfaces in NAT mode, in that order (assumed) |
| Scope | the root system of one device |

| | Cisco PIX 6.x (read only) |
|---|---|
| Address objects | the addresses of an entry, `name`, `interface NAME`; a host behind a `static` by its global address, as the access lists name it |
| Address groups | `object-group network`, nested |
| Services | protocols and ports of an entry, `object-group service`, ICMP types |
| Security rules | access lists bound with `access-group`; on interfaces without one, the implicit rules towards lower security levels for what translations cover, and conduits towards higher ones; a rule that permits more than the mandatory NAT lets through is flagged |
| NAT | exemptions, `static` addresses and ports, policy NAT, `nat` with its `global`s by best match, in Cisco's order |
| Scope | one PIX 6.x; PIX 7 and later are read as an ASA |

Not converted, and reported where a rule depends on it: security profiles,
schedules, user and group matches, URL categories, HIP profiles, application
filters, wildcard-mask and geography addresses, external dynamic lists,
internet-service (ISDB) policies, load-balancing virtual IPs, NAT64/NAT46,
Check Point access roles that name machines or a remote access client (roles of
networks and users are read; PAN-OS writes their users, the other targets
write such rules disabled), application objects, VPN communities and implied
rules, iptables match modules beyond addresses, ports and state, the `INPUT`
and `OUTPUT` chains, nftables rate limits, quotas and meters, sets filled at run
time, `fib`, `socket` and mark matches, chains at hooks other than forward and
tables of the bridge, arp and netdev families, ASA time ranges, identity (user and TrustSec) matches,
outbound access lists that do more than deny, NAT of ASA releases before 8.3,
the application, URL, user, VLAN, security group tag and dynamic object
conditions of FTD rules, its intrusion, file and SSL policies, what a prefilter
rule with the action Analyze does to the traffic inside a tunnel, Sophos web server
protection rules, Security Heartbeat conditions, MAC hosts and country groups,
pfSense schedules, URL table aliases, policy routing (a gateway on a rule),
tags, limiters and traffic shaping, match rules, NPt, IPv6 NAT, bogon
networks, the rules of the captive portal and of packages, OPNsense
GeoIP, URL, ASN and MAC aliases, TCP flags, rate limits and NPt, SonicWall ICMP service objects, users, schedules, source-port
services and the security services of a rule (Geo-IP, botnet filter), its
IPv6 and MAC address objects and Policy mode (SonicOSX), WatchGuard network
dynamic NAT and 1-to-1 NAT, proxy actions and schedules, Barracuda rule lists
(Cascade), NAT, App Redirect and the host firewall, Junos logical systems,
unified policies, schedulers and policy-based VPN, the NSX gateway firewall,
context profiles (layer-7 applications, FQDNs), extended expressions of
groups, identity firewall, rule schedulers, EtherType services, the Manager
API, AWS traffic from inside a VPC to its own public addresses, the network
ACLs of subnets traffic is routed through and the replies a stateless ACL
drops (reported), security group VPC associations, Azure Virtual Network
Manager's admin rules, an interface behind two network security groups
(reported), VPN gateways between virtual networks, RouterOS `input` and
`output` chains, raw and mangle rules, layer-7, content, TLS host and rate
matches, marks, address lists filled at run time, IPsec policy matches,
schedules, `redirect` and IPv6 NAT, Forcepoint aliases, element-based and
default NAT, VPN actions and matches, block lists, rule validity times and
connection limits, Terraform resources outside the input (other states, made by
hand), dynamic blocks and values a plan does not know (reported), the AWS Network
Firewall, WAF and Azure Firewall resources of a state (reported), Azure Firewall
application rules, threat intelligence, IDPS, TLS inspection and source NAT
(reported), AWS Network Firewall payload keywords, domain names, TCP flags,
fragments and managed rule groups whose rules are not shown, pf anchors,
included files, tables from files or filled at run time, `tagged`, queues and
scrub (reported), VyOS `input` and `output` and the local zone, `nat66`, static
NAT and the bridge firewall (reported), ScreenOS virtual systems, policy-based
VPN, authentication and IPv6 NAT, PIX `outbound` and `apply` lists, outside
NAT, `fixup` and `established` (reported), Meraki group policies, cellular and
VPN tables and layer 7 categories (reported), content filtering, Stormshield implicit rules, NAT of a
slot, time objects, inspection profiles and policy routing (reported), Huawei virtual systems, applications,
users, domain sets, regions and the local zone (reported), IOS control-plane and self-zone
policies, VRFs, policy routing, outside and route-map NAT, time ranges and layer-7
inspection (reported), Google Cloud secure tags, address
groups, FQDN, geography and threat intelligence matches, firewall endpoints and
security profiles, hierarchical policies left out of the export (reported),
routing, interfaces, VPN,
and everything else outside the policy.

## Roadmap

[TODO.md](https://github.com/jkobierczynski/FWShift/blob/HEAD/TODO.md) has the list. In short:

* **Firewall brands**, one per release: Sophos Firewall 0.6, Cisco Secure
  Firewall (formerly Firepower) 0.7, pfSense 0.8, SonicWall 0.9, WatchGuard
  0.10, Barracuda 0.11, Juniper SRX 0.12, nftables 0.18, VMware NSX 0.19,
  AWS security groups 0.20, Azure network security groups 0.21, MikroTik
  RouterOS 0.23, OPNsense 0.24, Forcepoint NGFW 0.25, Terraform (AWS and
  Azure) 0.26, Google Cloud firewall rules (and terraform-google) 0.27, Cisco IOS
  and IOS XE 0.28, Huawei USG 0.29, Stormshield SNS 0.30, Cisco Meraki MX
  0.31; Azure Firewall, AWS Network Firewall, pf and VyOS, with Juniper
  ScreenOS and Cisco PIX 6.x read only, 0.41; what is still open for each is in
  TODO.md.
* **Rule usage**, 0.13 to 0.17 ([docs/RULE_USAGE.md](https://github.com/jkobierczynski/FWShift/blob/HEAD/docs/RULE_USAGE.md)):
  rule identities and hit counters (0.13), Check Point logs (0.14),
  connections without a rule uid and iptables logs (0.15), PAN-OS and FortiOS logs (0.16) and
  narrower rules proposed from the use (0.17), all done, as fwanalyser did for Check
  Point.
* Audit and matrix: the zone and conduit model as a file to check a policy
  against, the equivalence check as a command and of a conversion (0.22,
  done), the networks behind a zone from the source (0.35, done), results as
  SARIF, CSV and HTML (0.36, done); next NAT in the comparison, zone ranks.
* Validation of the output on lab devices of every platform: [the lab](https://github.com/jkobierczynski/FWShift/blob/HEAD/lab/README.md)
  (0.32) scripts it for the cloud targets, five free images and five Marketplace images; nftables and iptables run
  in the test suite, AWS, Azure and Google Cloud have had their first runs (0.32.1), the others wait for theirs.

## Licence

Copyright (C) 2026 Jurgen Kobierczynski

FWShift is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

FWShift is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE. See the GNU General Public License in
[LICENSE](https://github.com/jkobierczynski/FWShift/blob/HEAD/LICENSE) for more details.

**Test data is synthetic.** Every configuration in this repository is written
by hand with documentation address ranges. Do not add configurations from real
networks, anonymised or not.
