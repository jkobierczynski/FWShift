# FWShift development notes

How the code is organised, the rules it follows, how to extend and test it,
and a log of what has been done. For using the tool, see the
[user manual](docs/MANUAL.md).

## Status

| | |
|---|---|
| Version | 0.40.0 (alpha) |
| Platforms | PAN-OS and Panorama (read XML, write `set` commands); FortiOS (read and write CLI configuration); Check Point (read Management API JSON, write a `mgmt_cli` script); Cisco ASA (read `show running-config`, also of an FTD; write ASA commands); Cisco IOS and IOS XE routers (read `show running-config`: interface access lists, object groups, the zone-based firewall, NAT; write commands for the zone-based firewall); Huawei USG (read `display current-configuration`: security zones, address and service sets, `security-policy`, `nat server`, `nat-policy`; write commands for the system view); Stormshield SNS (read the ConfigFiles as a `.tgz`: interfaces, objects, the active filter slot and the global one; write a script of serverd commands); Cisco Meraki MX (read the answers of the Dashboard API for one network: VLANs, objects, the outbound and layer 7 rules, port forwarding, 1:1 and 1:many NAT, the inbound table with NAT exceptions; write a curl script that puts the outbound and NAT tables); Cisco Secure Firewall managed by a Management Center (read the JSON of its REST API; write a Python script that loads a new policy through that API) or by its Device Manager (read the configuration export or the JSON of its API; write a file for the configuration import); Sophos Firewall, SFOS 18 and later (read and write the `Entities.xml` of *Import export*, plain or in its `.tar`); pfSense 2.6 and later (read `config.xml`; write the areas Aliases, NAT and Firewall Rules for a restore, for 2.7 and later); OPNsense 24.7 to 26.7 (read `config.xml`, both kinds of rule; write the areas Aliases, NAT and Firewall Rules for one series); SonicWall, SonicOS 6.5 and 7 (read the settings export `.exp`; write commands of the SonicOS 7 command line); WatchGuard, Fireware 12 (read the configuration file of Policy Manager; write its policy part, to merge into a configuration of the target); Barracuda CloudGen Firewall, 8.0 and later (read saved answers of its REST API; write a shell script that creates the rules through that API); Juniper SRX, Junos OS (read `display set` or the configuration in braces; write set commands for `load set`); iptables and ip6tables (read `iptables-save`, write `iptables-restore` files); nftables (read `nft list ruleset` text or JSON, write one table for `nft -f`); VMware NSX distributed firewall (read the JSON of the Policy API, hierarchical or list answers; write the body of one hierarchical `PATCH`); AWS EC2 security groups and network ACLs (read the JSON of the AWS CLI for one VPC; write a shell script of AWS CLI calls that creates new security groups); Azure network security groups (read the JSON of the Azure CLI, the REST API, an ARM template or Resource Graph; write an ARM template with a group per zone); MikroTik RouterOS 6 and 7 (read the output of `/export`; write a script for `/import` whose chains one change switches on); Forcepoint NGFW (read the answers of the SMC REST API for one policy, fetched by a read-only program FWShift writes; write a Python script that creates a new policy through that API); Google Cloud (read the JSON of gcloud for one VPC network: VPC firewall rules, global and regional network firewall policies, hierarchical ones when added, the instances; write a gcloud script that creates a new global network firewall policy); Terraform for AWS, Azure and Google Cloud (read `terraform show -json` of a state or a plan, or the raw state: the security groups, network ACLs and members of hashicorp/aws, the network security groups of hashicorp/azurerm, the firewall rules and policies of hashicorp/google; write HCL that creates the groups or the policy) |
| Tests | 6699, all passing (a dozen of them need root, and iptables or nft, and are skipped elsewhere); `mypy --strict` clean |
| Verified on devices | **iptables and nftables**: rulesets loaded into a Linux kernel and real packets forwarded through it (below; and the lab of 0.32.0, also on the author's machine). **AWS, Azure and Google Cloud**: the lab policy's conversion loaded into a real account by the lab, and real connections between instances checked (0.32.1, below). **FortiOS**: the lab policy's conversion loaded on a FortiGate-VM (FortiOS 8.0.1, AWS Marketplace) and real connections through it checked (0.32.1, below). **PAN-OS**: the same on a VM-Series (PAN-OS 11.2.15, AWS Marketplace). Nothing has been loaded on an ASA, an IOS router, a Huawei USG, a Stormshield firewall, a Meraki MX, a Sophos Firewall, a pfSense, a SonicWall, a Firebox, a CloudGen Firewall, an SRX, an NSX Manager, a MikroTik router, an OPNsense, a Forcepoint SMC, a Check Point management server, a Cisco Management Center or a Device Manager, and no Terraform output was applied with Terraform |
| Analysis | the audit, the zone matrix, rule usage from hit counters and logs, the zone and conduit model as a gate (`fwshift conduits`), the equivalence check (`fwshift compare`, `convert --compare`) |
| Security | an outside review (ChatGPT, October 2026) and the measures taken: `docs/security/SECURITY_REVIEW.md` |
| Next | the networks behind a zone from the source, NAT in the comparison, more targets read back; lab validation of the sample conversions (see `TODO.md`) |

## Layout

```
src/fwshift/
    model.py          the vendor-neutral policy model and its semantics
    parsers/
        panos.py      PAN-OS / Panorama XML  -> model
        fortios.py    FortiOS configuration  -> model
        checkpoint.py Management API JSON    -> model (inline layers flattened)
        asa.py        ASA running-config     -> model (bound access lists, NAT sections)
        meraki.py     Meraki Dashboard API answers -> model (VLANs as zones, the
                      outbound and layer 7 rules, NAT and what it lets in)
        stormshield.py Stormshield ConfigFiles (.tar/.tgz) -> model (interfaces,
                      objects, the global and the active filter slot)
        huawei.py     Huawei USG current-configuration -> model (security zones,
                      address and service sets, security-policy, nat server
                      before it, nat-policy after it)
        ios.py        IOS / IOS XE running-config -> model (interface lists in and
                      out, the zone-based firewall and NAT, composed for each
                      pair of zones where more than the inbound list decides)
        cisco.py      JSON of a Management Center or a Device Manager -> model
                      (sections and inheritance, the prefilter policy, NAT in
                      the order of the device)
        sophos.py     Sophos Entities.xml    -> model (exclusions, a rulebase per IP version)
        pfsense.py    pfSense config.xml     -> model (the order of pf, interface
                      groups, port forwards and the rules pfSense adds itself)
        opnsense.py   OPNsense config.xml    -> model (brought into the form the
                      pfSense reader reads, which a subclass of it reads with
                      what OPNsense does otherwise: tiers, flags per series,
                      aliases as pf tables, both kinds of rule and of NAT)
        forcepoint.py the answers of the SMC REST API -> model (templates and
                      insert points, Continue and Jump flattened, zones and
                      match expressions, expressions, each rule pinned to its
                      IP version)
        smc_dump.py   the read-only program that fetches those answers
                      (`fwshift script forcepoint-dump`): stands alone
        sonicwall.py  SonicOS settings export -> model (rules per pair of zones,
                      default rules, objects of SonicOS from the interfaces)
        watchguard.py Policy Manager XML     -> model (interfaces as zones, a
                      policy per pair of interfaces it names, static NAT actions)
        barracuda.py  CloudGen REST API JSON -> model (interfaces of source
                      entries as zones, exclusions, bi-directional rules)
        junos.py      SRX set lines or braces -> model (pairs of zones, then
                      global policies; books of zones; NAT before the policy)
        iptables.py   iptables-save output   -> model (chains flattened)
        nftables.py   nft list ruleset, text or JSON -> model (every base chain
                      at the forward hook combined; chains, sets and maps
                      flattened)
        nsx.py        NSX Policy API JSON -> model (categories, sequence
                      numbers, jump to Application, default rule; applied-to,
                      direction and IP version as far as they decide)
        aws.py        AWS CLI JSON -> model (groups as the addresses of their
                      interfaces; outbound rules outside the VPC, pairs of
                      outbound and inbound rules inside; network ACLs)
        azure.py      Azure JSON (CLI, REST, template, Resource Graph) -> model
                      (a zone per group; the outbound and inbound lists of
                      two groups composed; templates worked out)
        gcp.py        gcloud JSON for one VPC network -> model (the steps in
                      Google Cloud's order, goto_next cut out, tags and service
                      accounts as the addresses of the instances, egress and
                      ingress composed between instances)
        terraform.py  Terraform state or plan JSON -> the answers of the AWS
                      CLI, the Azure CLI or gcloud, read by aws.py, azure.py or
                      gcp.py (echoes of a refresh once, unknowns of a plan from
                      the configuration)
        routeros.py   RouterOS /export -> model (interface lists as zones;
                      chains flattened with the conditions of nftables.py,
                      returns taken away exactly; the !dstnat exception)
    emitters/
        panos.py      model -> PAN-OS set commands
        fortios.py    model -> FortiOS CLI configuration
        checkpoint.py model -> shell script of mgmt_cli calls
        asa.py        model -> ASA commands (access lists per interface, twice NAT)
        meraki.py     model -> a curl script for the Dashboard API (the outbound
                      table, port forwarding, 1:1 and 1:many NAT)
        stormshield.py model -> a script of serverd commands (objects, one
                      filter slot, NAT)
        huawei.py     model -> commands for the system view of a USG (zones,
                      address and service sets, rules, defaults, nat server,
                      nat-policy)
        ios.py        model -> commands for the IOS zone-based firewall (an
                      access list and class map per rule, a policy per zone pair)
        cisco.py      model -> the script for a Management Center (fmc_loader.py
                      and the policy as data), or the import file of a Device
                      Manager
        fmc_loader.py the program of that script: stands alone, imports
                      nothing of the package, and is shipped as it is
        sophos.py     model -> Entities.xml (a rule per IP version, flat groups)
        pfsense.py    model -> the areas aliases, nat and filter of a pfSense
                      configuration (a rule per arrival interface)
        opnsense.py   model -> the same decisions, in the form of an OPNsense
                      series (a subclass of the pfSense emitter whose nodes
                      become rules, aliases and NAT of the newer models)
        forcepoint.py model -> a Python script: smc_loader.py and the policy as
                      data (elements, zones, a rule per IP version it can match)
        smc_loader.py the program of that script: stands alone, shipped as it is
        sonicwall.py  model -> SonicOS 7 commands (a rule per pair of zones and
                      IP version, a rule that denies at the end of each pair)
        watchguard.py model -> the policy part of a Policy Manager file (aliases
                      of zone and address, static NAT actions in policies)
        barracuda.py  model -> a shell script of REST calls (rules created
                      deactivated at the top, then activated in order)
        junos.py      model -> SRX set commands (policies per pair of zones,
                      the end of the model as global policies, NAT rule sets)
        iptables.py   model -> iptables-restore / ip6tables-restore file
        nftables.py   model -> one table for nft -f (anonymous sets; NAT
                      through the iptables planner)
        nsx.py        model -> the body of one hierarchical PATCH (services,
                      groups, one security policy; zones as networks)
        aws.py        model -> a script of AWS CLI calls (allow rules without
                      the deny rules above them, both ends, groups cut by
                      address)
        azure.py      model -> an ARM template (a group per zone, each list in
                      blocks per remote zone, with the default of the source)
        gcp.py        model -> a gcloud script: one global network firewall
                      policy, each rule per IP version for ingress and egress
        terraform.py  model -> HCL: the groups of aws.py (a subclass of its
                      emitter), the template of azure.py or the policy of
                      gcp.py, as resources
        routeros.py   model -> a script for /import (chains of its own, the
                      jumps to them disabled; NAT through the iptables planner)
    regions.py        sets of connections as boxes (IP version, sources,
                      destinations, services): subtraction, and services back
                      to entries; for AWS, which cannot block
    transform.py      passes shared by the emitters: hardening of names,
                      references, placeholders, names, application lowering,
                      NAT destination rewriting, NAT order, pruning
    audit.py          the audit: what rules match as sets, the checks, the
                      actions (accept, disable, reorder), before and after;
                      use from hit counters (UNUSED_RULE, NO_USAGE_EVIDENCE)
    hits.py           hit counters from a file (PAN-OS rule-hit-count, FortiOS
                      monitor), put on the rules by their source identifiers
    logreaders/
        checkpoint.py Log Exporter (syslog, splunk, cef) and show-logs -> connections
                      with the match table of the rules the gateway named
        iptables.py   the kernel lines of LOG rules (syslog, journal) -> connections
                      with their interfaces, no rule
        panos.py      PAN-OS traffic logs (syslog CSV, export) -> connections with the
                      rule's UUID and name
        fortios.py    FortiOS traffic logs (key=value) -> connections with the
                      policy's UUID and ID
    simulate.py       first match on the audit's sets for a connection whose log
                      names no rule: certain or possible
    narrow.py         narrower rules from what the logs show (WIDER_THAN_TRAFFIC)
    usage.py          fwshift usage: the store (SQLite), attribution of connections
                      to rules, objects and services, evidence, the reports
    matrix.py         the zone matrix: what each zone may reach in each other
                      zone, from the sets of the audit; zones of the policy or
                      zones given as networks
    conduits.py       the zone and conduit model: the file, a policy checked
                      against it through its matrix, a draft from a policy
    compare.py        the equivalence check: what two policies allow, per pair
                      of zones, from above and from below, and every connection
                      whose verdict differs; labels for applications, users,
                      categories, schedules and what cannot be read
    appmap.py         application/port table, protocol tables, reserved names
    netutil.py        IP intervals
    xmlread.py        XML from outside: no document type, whatever the encoding
    names.py          naming rules of the targets
    report.py         findings, item status, text and JSON report
    options.py        conversion options
    cli.py            command line; also the small Python API (load, convert)
.github/workflows/
    ci.yml            mypy and the tests, on every push
    release.yml       on a version tag: a release with a zip of the project, a
                      single-file fwshift.pyz, a wheel and a source distribution
tests/
    data/             one synthetic sample per format
    data/expected/    their conversions and reports, byte for byte
    tools/            the scripts that write the Check Point sample and its logs, the
                      iptables logs of iptables_logged.rules, the PAN-OS and
                      FortiOS logs (and panos_logged.xml), the two
                      Cisco Secure Firewall samples and the SonicWall,
                      WatchGuard, Barracuda and Juniper samples, the nftables
                      sample (written by nft itself), the NSX, AWS, Azure, Google Cloud, Terraform, IOS, Huawei, Stormshield, Meraki, RouterOS and OPNsense samples, the zone model,
                      and the kernel checks for iptables and nftables
    helpers.py        loaders, and readers for emitted PAN-OS, FortiOS,
                      Check Point, ASA, Sophos and Cisco Secure Firewall output;
                      a pfSense that judges packets from its configuration;
                      an OPNsense that does, for both kinds of rule and NAT,
                      and restores areas as OPNsense does;
                      a SonicWall that judges by an export and by commands;
                      a Firebox that judges by its configuration file;
                      a CloudGen Firewall that judges by API answers or a script;
                      an SRX that judges by set lines
    test_parsers.py   netutil, FortiOS syntax, PAN-OS and FortiOS parsers
    test_emitters.py  PAN-OS and FortiOS emitters
    test_semantics.py one small configuration per semantic trap
    test_iptables.py  iptables both ways, a packet simulator, cross-format NAT
    test_nftables.py  nftables both ways, against a walk through the chains as
                      the kernel runs them; with nft, listings of the kernel
    test_nsx.py       NSX both ways, against a judge of Policy API JSON that
                      shares no code with the parser
    test_aws.py       AWS both ways: a judge of a VPC (groups, ACLs, public
                      addresses) and a judge of the emitted script
    test_azure.py     Azure both ways: a judge of groups as Azure decides
                      them (two lists in priority order) and a judge of the
                      emitted template
    test_gcp.py       Google Cloud both ways: a judge of a network (the steps,
                      tags, instances) and a judge of the emitted script
    test_terraform.py Terraform both ways: random VPCs, groups and networks of
                      test_aws.py, test_azure.py and test_gcp.py written as
                      states and plans, against their judges; the HCL read by a
                      reader of its own and judged by the script and template
                      judges
    test_routeros.py  RouterOS both ways: a judge that walks filter chains as
                      the router does, for random exports and for the script
    test_checkpoint.py Check Point both ways, with simulators for an export
                      and for an emitted script
    test_meraki.py    Meraki both ways: random networks written as Dashboard
                      answers and a judge of their own; the emitted script read
                      back and judged the same way, also after a round trip, and
                      what its NAT lets in against the model
    test_stormshield.py Stormshield both ways: random firewalls written as
                      ConfigFiles and a judge of their own; the emitted script
                      read back and judged the same way, also after a round trip
    test_huawei.py    Huawei USG both ways: random USGs written as current
                      configurations and a judge of their own (nat server, first
                      match, the defaults); the emitted commands read back and
                      judged the same way, also after a round trip
    test_ios.py       Cisco IOS both ways: random routers written as running
                      configurations and a judge of their own (lists, NAT, the
                      zone-based firewall); the emitted commands read back and
                      judged the same way
    test_asa.py       Cisco ASA both ways, with a random ASA that judges
                      packets itself and a strict reader of emitted commands
    test_sophos.py    Sophos Firewall both ways, against a strict reader of
                      Entities.xml that shares no code with the parser
    test_cisco.py     Cisco Secure Firewall both ways and for both managers:
                      a made-up device that judges packets, a strict reader
                      of what is written, a made-up Management Center that
                      the script is run against
    test_pfsense.py   pfSense both ways: random configurations against the
                      judge in helpers.py, emitted files restored into it
    test_opnsense.py  OPNsense both ways, per series, against the judge in
                      helpers.py; pfSense converted and restored on an OPNsense
    test_forcepoint.py Forcepoint both ways: random SMC answers against the judge
                      in helpers.py; emitted scripts run against the made-up
                      SMC of fake_smc.py, read out with the dump program and
                      judged; the loader and the dump program
    fake_smc.py       a made-up SMC: the calls of its REST API the loader and
                      the dump program make, strict about what is sent
    test_sonicwall.py SonicWall both ways, against the two judges in helpers.py
    test_watchguard.py WatchGuard both ways, against the judge in helpers.py
    test_barracuda.py Barracuda both ways, against the judge in helpers.py
    test_junos.py     Juniper SRX both ways, against the judge in helpers.py
    test_usage.py     rule identities, install-on targets, Check Point access
                      roles (against the cell as Check Point reads it), hit
                      counters and the audit of use
    test_logs.py      the log readers, the store, attribution (the defects of
                      fwanalyser, against a walk through the addresses) and
                      evidence; the usage command
    test_simulate.py  the simulation, against a walk through the rules in every
                      world of the rules the model holds approximately; the
                      iptables LOG reader and the usage of an iptables policy
    test_traffic_logs.py the PAN-OS and FortiOS readers, attribution by the
                      rule's identifiers (against a reference), their usage
    test_narrow.py    narrower rules: never wider than the cell, holding what
                      was seen; proposals read back
    test_audit.py     the audit, against a walk through every packet of a
                      small world
    test_matrix.py    the zone matrix, against the same walk: every packet
                      that gets through is in it, and nothing else
    test_conduits.py  the zone and conduit model, against a walk through
                      packets: what the policy allows beyond the model is found
    test_compare.py   the equivalence check, against a walk through labelled
                      packets (applications, users, a dynamic group whose members
                      only the walk knows): every difference is found, a certain
                      one is real; iptables and nftables output read back
    test_cli.py       command line, golden files
    test_lab.py       the lab: its plan against the judge, the probe, every run
                      dry, and real runs of nftables and iptables in namespaces
lab/                  the lab (lab/README.md): the converted lab policy on real
                      targets (cloud networks, local images, Marketplace
                      firewalls), checked with real connections
docs/MANUAL.md        user manual
docs/guide.html       field guide: the features on one page, per brand what to
                      export, how to load and what to watch for (from the manual)
docs/RULE_USAGE.md    design of rule usage from hit counters and logs (0.13.0
                      to 0.17.0)
TODO.md               what is planned, release by release
```

No third-party dependencies at run time. Python 3.9 is the floor because it is
the system Python of RHEL 9.

## How a conversion runs

```
bytes ──parser──▶ Policy ──emitter──▶ text
                    │                  ▲
                    └── Report ────────┘   (findings from both sides)
```

1. `cli.load` picks the parser. The parser returns a `Policy` and records
   findings about what it could not read.
2. `cli.convert` checks the option values, runs `transform.harden` on the
   model (control characters out of every name, host names and ports that are
   none made unusable), registers every rule and object in the `Report`, in
   source order, then calls the emitter.
3. The emitter works on a deep copy. In order: `apply_zone_map`,
   `ensure_references` (placeholders for dangling references),
   `sanitize_names`, target-specific lowering, rendering.

Parsers know one vendor and the model. Emitters know one vendor and the model.
Neither knows the other vendor; where an emitter needs to know where a policy
came from (same-vendor conversions, default behaviour), it reads
`Policy.vendor` and the `default_intrazone` / `default_interzone` fields.

## The neutral model

`model.py` states the semantics every parser normalises to:

* Security rules match **pre-NAT** addresses and ports and the **post-NAT**
  destination zone.
* `any` is any address of either IP version. IPv4-only "any" is the literal
  `0.0.0.0/0`, IPv6-only "any" is `::/0`.
* A negate flag covers both IP versions.
* Rule members are object names or literals; a name wins over a literal.
* Port lists use PAN-OS syntax (`80,443,8000-8080`); empty means all ports.
* Application names are PAN-OS App-ID names.
* An FQDN is resolved for both IP versions unless `fqdn_family` says otherwise.
* NAT is an ordered, first-match rulebase separate from the security rules.

A vendor whose behaviour differs has to be translated *in its parser and
emitter*, never by bending the model. FortiOS, iptables and ASA are the
examples: they look rules up after destination NAT, so their parsers call
`rewrite_destinations(to_post_nat=False)` and their emitters
`to_post_nat_lookup`. ASA is also the example for zones: its access lists name
no outgoing interface, so its parser works the destination zones out (from
what an ASA never forwards, and from routes) and its emitter has to get rid of
them again.

A few fields tell an emitter what kind of platform the rules came from, so
that it need not know the vendor:

| Field | Meaning |
|---|---|
| `default_intrazone`, `default_interzone` | what happens to traffic no rule matches |
| `lookup_after_dnat` | the source looks rules up after destination NAT; a target of the same kind undoes what the parser did and withdraws its findings |
| `NatRule.combines` | per NAT rule: the source applies it together with one rule of the other direction, instead of one rule, first match. Set for iptables, FortiOS, ASA and Check Point automatic rules (`transform.note_nat_order`) |
| `Rule.egress_implied` | the source rule named no destination zone; the zones in the model were worked out (ASA). A target that cannot match the outgoing interface loses nothing by leaving them out |
| `DestNat.spread` | the translation picks one of several addresses per connection (iptables `DNAT` to a range) instead of mapping address for address. A rule for one of them cannot be given "the same part of the other side" |
| `Rule.nat_added` | the destinations a parser of a post-NAT platform added to reach the pre-NAT model, with the origins of the NAT rules they were added for. A target of the same kind takes exactly these away again and leaves the rest of the rule alone |
| `named_translations` | a rule of the source that names the object of a destination NAT itself applied to the translated traffic (a FortiOS virtual IP in a policy). Such a member is rewritten for a target of the same kind too |

Two fields are for the audit only:

| Field | Meaning |
|---|---|
| `Rule.handling` | what the source rule does to a session besides its verdict, logging and profiles, as far as a parser reads it: NAT and a traffic shaper in a FortiOS policy (and every other key of a policy that the parser does not model and that is not switched off), a PAN-OS log forwarding profile, QoS marking and the like, the track setting of a Check Point rule. Two rules handle traffic "the same way" only when this is equal too. No emitter reads it |
| `Options.written` | not in the model but next to it: when it is a list, an emitter adds the copy of the policy it writes its output from (zones mapped, names made valid, destinations rewritten for the side of NAT the target matches on). The audit proves on it that a rule it disables changes nothing for the target either |

Three fields carry what the source knows about a rule beyond what it
matches. No emitter writes them; `--to json` shows them:

| Field | Meaning |
|---|---|
| `Rule.source_ids` | the source platform's own identifiers of the rule, which its hit counters and logs use: `checkpoint.rule_uid`, `checkpoint.layer_uid`, and for a rule of an inline layer `checkpoint.parent_rule_uid` (the direct parent) and `checkpoint.rule_path` (every rule uid on the way, outer first); `panos.name`, `panos.uuid`; `fortios.policyid`, `fortios.uuid`. A rule the parser split or combined keeps those of its source rule. The implicit cleanup of an inline layer has `checkpoint.implicit` and no rule uid. Counters and log lines are matched by these, never by position (fwanalyser keyed by rule number, and history moved to the wrong rule after a reorder) |
| `Rule.targets` | the devices the source installs the rule on, by name (Check Point install-on, Panorama targets that are not negated); empty for all. `DEVICE_TARGET` still says that a target is one firewall |
| `Rule.hits` | the hit counter of the rule (`HitCount`): count, first and last hit, since when it counts where the source says, where it was read, what limits it, and whether it may leave out firewalls the rule is on. The audit's `UNUSED_RULE` and `NO_USAGE_EVIDENCE` read it (`docs/RULE_USAGE.md`) |

A finding on a rule that is about one NAT rule carries the origin of that NAT
rule (`Finding.subject`, not shown in the report). `to_post_nat_lookup` uses
it to withdraw, on a target of the same kind as the source, only the findings
of NAT rules the target really gets.

`builtin` on an object names the vendor on which the object exists without a
conversion creating it: a predefined service, a Check Point gateway, a service
that an ASA access list entry spells out, the address of an ASA interface
(`raw` then says `interface <name>`). An emitter for that vendor refers to it
in its own way; every other emitter treats it as an ordinary object.

The resolvers in `transform.py` (`address_intervals`, `known_intervals`,
`families`, `flatten_services`) walk groups inside groups. They resolve a
group once per call and return each address once: with two groups per level
that both hold both groups below, anything else doubles with every level.
`transform.harden` makes groups that hold themselves unusable before any
emitter sees them. A walker of your own needs the same two things.

## Rules the code follows

1. **Never widen silently.** If the target cannot express a match, the rule is
   emitted disabled (`transform.disable_rule`) or the NAT rule is skipped, with
   a `REVIEW` finding. An enabled approximation gets at least `APPROX`.
2. **Never read absence as "any".** A missing element, an unreadable value, or
   an attribute the parser does not know goes into `Rule.unsupported`, a
   tainted object, or a `REVIEW` finding.
3. **Keep every rule, in order.** Disabled rules stay in place so that the
   position of the gap is visible.
4. **Keep references resolvable.** Unconvertible objects become placeholders
   (`0.0.0.0/32`, `tcp/1`) that match nothing.
5. **Say what was done.** Anything the converter adds, renames, splits or
   merges is in the report.
6. **Narrower beats wider when unsure**, except for deny rules, where narrower
   is the dangerous direction: treat those separately (`APP_TO_PORTS` on a deny
   is `REVIEW`).

### Severity of findings

| Severity | Use it when |
|---|---|
| `INFO` | The result is exact; the reader should still know (rename, split, merged NAT rule). |
| `APPROX` | The rule is enabled and its semantics changed in a known, bounded way. |
| `REVIEW` | A person must decide: the rule is disabled or skipped, or it is enabled and may be wider or narrower than the source. |

Codes are upper-case identifiers and are part of the interface (JSON report,
manual section 7). When adding one, add it to the manual.

## Adding a vendor

The work is:

1. **Parser** `parsers/<vendor>.py` with `parse(data: bytes, report, ...) -> Policy`.
   Normalise to the model semantics above. Give every rule a unique `name` and
   set `origin` to it; the report is keyed by `origin`. Put anything that
   narrows a match and cannot be modelled into `Rule.unsupported`.
2. **Emitter** `emitters/<vendor>.py` with `emit(policy, report, options) -> str`.
   Start with the shared passes in `transform.py`; write the lowering so that
   every lossy step adds a finding.
3. **Register** both in `cli.py` (`load`, `EMITTERS`, `VENDORS`, format
   detection, options for scope selection).
4. **Names**: add the target's rules to `names.py` and its reserved names to
   the emitter.
5. **Sample and tests**: a synthetic configuration in `tests/data`, golden
   conversions to and from the existing vendors, and a case in
   `test_semantics.py` for every behaviour that differs from the model.
6. **A simulator** where the format allows one. For iptables, Check Point
   and ASA the tests evaluate packets against the source, the model and the
   emitted output and require the same verdict; that found defects no
   hand-written case had. Build the judge of the source from the generator's
   own data, not from the parser under test, and give the generator NAT: the
   one silent error of the ASA review that the tests could have found was a
   NAT rewrite they had no way to see.
7. **Manual**: how to get the input (section 3), conversion notes in section
   8, new findings in section 7, how to load the output (section 10).

## Testing

```sh
pip install -e ".[dev]"
python -m pytest -q
python -m mypy
```

* **Sample tests** convert `tests/data/*` and assert on the parsed result.
  `tests/helpers.py` reads emitted FortiOS back with the project's own tree
  parser and emitted PAN-OS `set` commands with a small indexer, so assertions
  are on structure, not on text.
* **Golden files** in `tests/data/expected/` hold the full conversions and
  reports. After an intended change:

  ```sh
  FWSHIFT_UPDATE_GOLDEN=1 python -m pytest tests/test_cli.py
  git diff tests/data/expected
  ```

  Review that diff like code: it is the output users get.
* **`test_semantics.py`** has one small configuration per trap. Every defect
  found in review has a test there. Add one whenever a conversion rule changes.
* **Round trip**: FortiOS -> model -> FortiOS -> model is asserted equal for a
  configuration without NAT. PAN-OS output cannot be read back, since the
  parser reads XML and the emitter writes `set` commands.
* **Packet-level equivalence** (`test_iptables.py`, `test_checkpoint.py`,
  `test_asa.py`).
  Random models are emitted and random packets are evaluated against the
  model and against the output: an iptables ruleset walked like the kernel
  walks it, a `mgmt_cli` script replayed call by call (every reference must
  exist when it is used) and then matched like a gateway matches layers. In
  the other direction random rulesets and random exports with nested inline
  layers are evaluated directly and through the parser. A ruleset in which
  the parser flagged a rule is set aside, and the tests require that most
  are not.

  Know what these tests cannot see: the iptables simulator reads rules with
  the project's own `parse_rule`, so a misreading of one line is invisible to
  it, and the iptables and Check Point generators produce no NAT. The cases a
  reviewer found that way are hand-written tests at the end of both files.

  For ASA the test builds a random ASA (`random_lab`): interfaces with
  security levels, `same-security-traffic`, lists per interface and a global
  one, every form of an entry, optionally routes and NAT. Each entry is
  generated as text together with a predicate, so the lab judges a packet
  without any of the project's code. The model read from the text has to
  agree with it; so has the ASA output for that model, read by
  `helpers.AsaConfig`, which is strict about what an ASA would take (objects
  before use, one name once, no empty groups) and is not the project's
  parser. In the other direction random models are written for an ASA with
  `--zone-network` for every zone and compared packet by packet; with
  networks that are incomplete in the ways a person leaves them incomplete,
  the output may allow less than the model but never more without a finding
  on the rule that decides. None of this
  replaces an ASA: the lab and the reader are both written from the same
  reading of Cisco's documentation as the code they check.
  For Sophos Firewall, `helpers.SophosConfig` reads an `Entities.xml` the
  way an import would and decides about packets as the firewall would:
  entities in the order of the file, each name defined before it is used and
  only once whatever its case, a host of the IP version of what uses it,
  only element names and values that the API documentation or Sophos's SDK
  show, a rulebase per IP version with each rule placed by its `Position`,
  first match, exclusions that apply together. It is the judge in both
  directions: for random models written by the emitter (with every
  combination of negated fields), and for random files (`random_entities`,
  with exclusions of one to three kinds and rules placed at the top, the
  bottom, before and after others) read by the parser. NAT has an oracle
  too, small as it is: the first rule that matches and what it translates
  to, for random NAT models and random NAT files. A mutation check (38 ways
  to break the parser and the emitter, among them the defects of review
  round 14) is not part of the suite; all were caught when it was run. As with the ASA, the reader is written
  from the same reading of the documentation as the code it checks.
* **The kernel** (`test_iptables.py`, the tests marked `needs_kernel`). Where
  the test host allows it (root, `unshare`, iptables), emitted rulesets and
  the converted samples are loaded with `iptables-restore` into a network
  namespace of their own, saved again and compared with the model; random
  hand-written rulesets are parsed both as written and as `iptables-save`
  prints them. Elsewhere these tests are skipped.
* **Real packets** (`tests/tools/kernel_check.py`, not part of the suite).
  Builds three veth pairs in a private network namespace, loads a ruleset,
  injects TCP, UDP, ICMP and GRE packets on one pair and watches whether they
  come out of another, for random models (emitter) and random rulesets
  (parser). Needs root and `pyroute2`:

  ```sh
  unshare -n python3 tests/tools/kernel_check.py 40
  ```

  Last run (40 seeds): 75 rulesets, 13836 packets, of which 5998 forwarded,
  on kernel 6.18 with iptables 1.8.10 (nf_tables): the kernel and the model
  agreed on every packet. Half of the packets are aimed at allow rules, so
  that "forwarded" is tested as much as "dropped". It covers the `filter`
  table for IPv4; NAT and IPv6 forwarding are not exercised.
  `tests/tools/nft_kernel_check.py` does the same for nftables, with the
  generators of `test_nftables.py` (`unshare -n python3
  tests/tools/nft_kernel_check.py 40`). Last run (40 seeds): 111 rulesets,
  20216 packets, 8764 forwarded, on kernel 6.18 with nft 1.0.9: the kernel
  and the model agreed on every packet.
  For Cisco Secure Firewall there are three judges, none of them the
  project's parser. `Lab` is a made-up device: random zones, objects, access
  rules in sections with an inherited policy, a prefilter policy, and for
  each a predicate that says what the device does with a packet; `Manager`
  writes what a Management Center answers for it, or what a Device Manager
  exports. The model read from that JSON has to agree with the lab on every
  packet. `helpers.CiscoConfig` reads what the emitter writes, the plan of
  the script or the import file, strictly: an object exists before it is
  used (for a Management Center: an earlier call created it), a name is
  given once whatever its case, a group has members, holds no port group and
  no host name, and a rule says only what a rule of that manager can say.
  `FakeFmc` is a made-up Management Center that speaks the REST API as far as
  the script uses it (tokens that run out, paging, bulk calls, "too many
  requests", names that are taken, objects in use that cannot be deleted):
  the script is run against it, over a socket as well, and what it built is
  read back by the parser and compared packet by packet with the model. A
  mutation check (95 ways to break the parser, the emitter and the script) is
  not part of the suite; when it was run, the ones the tests did not catch
  got tests. All three judges are written from the same reading of Cisco's
  documentation and tooling as the code they check: they find where the code
  disagrees with that reading, not where the reading is wrong.
* `tests/tools/make_checkpoint_sample.py` writes `checkpoint_sample.json`.
  The shape of that export follows the API documentation; it has not been
  compared with the output of a real management server.
  `tests/tools/make_cisco_samples.py` writes `fmc_sample.json` and
  `fdm_sample.txt` with the builder of the tests; neither has been compared
  with what a manager gives.

Test data is synthetic: hand-written, with RFC 1918, RFC 5737 and RFC 3849
addresses. Do not add configurations from real networks, anonymised or not.

CI (`.github/workflows/ci.yml`) runs mypy and pytest on Linux for Python 3.9
to 3.13, and on Windows and macOS for 3.12.

## Releasing

A version tag gets a GitHub release with its packages
(`.github/workflows/release.yml`):

| Package | |
|---|---|
| `fwshift-X.Y.Z.zip` | the project as tagged, under one directory: sources, tests, sample configurations, manual |
| `fwshift-X.Y.Z.pyz` | one file that runs with `python3 fwshift-X.Y.Z.pyz ...` (Python 3.9 or newer); nothing to install |
| `fwshift-X.Y.Z-py3-none-any.whl`, `fwshift-X.Y.Z.tar.gz` | the wheel and the source distribution, for pip |

To release:

1. Set `__version__` in `src/fwshift/__init__.py`, and write the entry
   `### <date>: version X.Y.Z` in the development log below. What stands under
   its `**Built**` becomes the text of the release. The version also stands in
   the Status table above, the manual ("This manual covers version"), the
   README (its status line and the `.pyz` names) and `docs/guide.html` (its
   eyebrow and the `.pyz` names); `test_cli.py` checks them all.
2. Run the tests with the oldest Python the package supports (3.9) as well as
   a current one: syntax that only newer releases take (a backslash in an
   expression of an f-string, before 3.12) compiles here and fails there.
3. Commit, then tag and push the tag:

   ```sh
   git tag v0.7.0
   git push origin v0.7.0
   ```

The workflow refuses a tag that is not the version the package says, runs
mypy and the tests, builds the packages, and checks them before anything is
published: the zip unpacks to the project, the single file prints its
version, converts a sample to the byte and hands on its exit status, the
wheel installs. A release that exists already gets its packages replaced.

For a version that was tagged before the workflow existed, run it by hand
(*Actions > Release > Run workflow*) and give the tag. Its steps take nothing
from the tree but the sources, so they work for every tag; `skip_tests` is
there for an old tag whose tests no longer run on today's tools.

## Design decisions

| Decision | Reason |
|---|---|
| Neutral model with parsers and emitters | Six formats need twelve components instead of thirty pairwise converters; a seventh adds two. |
| Model follows PAN-OS for NAT and matching | PAN-OS and Check Point both match pre-NAT; FortiOS is the exception and is handled at its edges. |
| Disabled rule instead of best guess | A disabled rule is visible and safe; a guessed rule is neither. |
| Central NAT for FortiOS output | It is the FortiOS model that maps one-to-one onto a NAT rulebase. Per-policy NAT would need NAT rules to be merged into security policies, which is lossy in the general case. Cost: it must be enabled on the FortiGate. |
| Small application table, not a copy of App-ID | A port-based policy can only express ports. A table that is small and readable can be checked; `--app-map` covers the rest. |
| `set` commands for PAN-OS output | They can be pasted into any PAN-OS or Panorama CLI and merged into an existing configuration; XML would have to replace or be merged by hand. |
| PAN-OS output holds no comments | The CLI has no comment syntax; everything goes to the report instead. |
| `edit 0` for FortiOS policies | Appends without colliding with existing policy ids. `--policy-id-start` exists for scripted setups. |
| iptables: `FORWARD` and `nat` only | The other platforms filter what passes through them; `INPUT` and `OUTPUT` protect the host itself and have no counterpart. Writing them would also lock people out of the host they load the file on. |
| nftables: one table, replaced whole | `table` / `delete table` / `table { ... }` in one file is one transaction: the table is replaced at once and nothing else is touched. `flush ruleset` would wipe firewalld, Docker and libvirt too. |
| nftables: base chains combined into one list | The kernel runs every base chain at a hook; the model has one rulebase. A rule that accepts is followed by the next chain's rules under it, which is exact and keeps the order of logging. |
| NSX: one hierarchical `PATCH` | One call creates services, groups and the policy together, or none of them; a `PATCH` changes only what it names. A policy of category Application with sequence number 1 lands where a person can see and move it. |
| Forcepoint: read the REST API, not the XML export | The API is documented and versioned; the XML export has no published format, and its import renames or overwrites on conflicts. The SMC answers one element at a time, so FWShift ships a read-only program that fetches what one policy needs. |
| Forcepoint: write a program for the REST API, a new policy on a template | As for a Management Center: every reference needs the href the SMC gives, and a program can look before it creates, reuse a predefined element only when it matches exactly, keep a journal and undo. It never installs a policy on an engine. |
| Forcepoint: a jump is flattened | The model has one rulebase. Each rule of the sub-policy, limited to what the jump rule matches, in its place, with nothing after them, is exact: when nothing matches, the next rule decides, as on the engine. |
| Forcepoint: a rule per IP version it can match | An SMC keeps IPv4 and IPv6 rules apart, and an element of the other version in a rule is refused when the policy is installed: a rule takes the part of its groups of each version. |
| NSX: zones as the networks behind them | The distributed firewall has no zones and runs at every workload. A rule between zones is written for the networks of `--zone-network`, as for Barracuda; an allow rule whose zones have none is written disabled. |
| NSX: applied-to and direction read only as far as they decide | NSX checks a connection at both ends. An allow rule that applies to one end, or to one direction, does not decide alone what the other end does; it is flagged or written disabled rather than read as allowing everywhere. |
| AWS: allow rules without the deny rules above them | A security group cannot block and has no order. What a first-match allow rule allows is its match without the matches of the blocking rules above it, which the boxes of `regions.py` hold exactly; earlier allow rules need not be taken out, the result is a union. |
| AWS: every piece on both ends, groups cut by address | A group's rule names one side; the other is the interface. Written as an inbound rule at the destination and an outbound rule at the source, each end lets through only what the policy allows between the two, which is exact without knowing which addresses are in the VPC. Every address in one group per IP version keeps the number of groups per interface at one or two. |
| AWS: new groups, attached to nothing | EC2 has no transaction. Groups without members change no traffic, so a script that stops halfway is harmless; attaching replaces the groups of an interface and is left to a person. |
| AWS: read without zones | A group is a set of interfaces, not a place; an interface carries up to sixteen. The VPC's addresses are a group of the model, so a target that needs no zones (NSX, AWS) needs no options. |
| Azure: each group a zone, two groups composed | A connection between resources behind two groups passes the outbound list of the one and the inbound list of the other. As one first-match list of the model: each outbound deny rule, and for each outbound allow rule the inbound rules cut to it. Exact where the cuts can be worked out; where they cannot, an allow rule is not converted and a deny rule blocks all it blocked. |
| Azure: a group per zone, blocks per remote zone | A security rule names addresses, not zones. Each list is cut into a block per remote zone, kept to its networks and ended by that zone's default, so every address of a zone is decided in its block; the zones of the default route come last, and only for their IP versions. |
| Azure: templates worked out, or refused | An exported or Bicep-built template is a common way to hold groups. Its expressions are worked out where they can be (parameters with defaults, variables, the common functions, copy loops, conditions); a name that cannot be worked out refuses the template, any other field leaves its rule not converted, so nothing goes missing silently. |
| RouterOS: chains of its own, switched on by one change | An import stops at the first line the router refuses and keeps the lines before it. Rules in `fwshift-forward` that nothing jumps to change no traffic, so a script that stops halfway is harmless; the jumps from `forward`, `dstnat` and `srcnat` come last, disabled, for a person to enable in Safe Mode. The script never writes `input` or `output` and never removes anything. |
| RouterOS: the chain ends with the policy's default | What falls off a custom chain goes back to `forward`, whose own rules and default accept would then decide it. An explicit accept or drop at the end makes the chain decide everything, as the source did. |
| RouterOS: interface lists as zones when they do not overlap | The lists are what a RouterOS administrator thinks in (`LAN`, `WAN`). Where they overlap, or a rule names part of one, every interface is a zone and a list its members, which is exact. |
| OPNsense: the pfSense reader and emitter, with what OPNsense does otherwise | OPNsense writes the same kind of pf ruleset, and two thirds of what pfSense does with a configuration (interfaces, aliases of networks, the per-family halves of a rule, leaving rules, NAT plans) holds. The parser brings a configuration into the pfSense form (flags as the series reads them, both kinds of rule as rules of `<filter>` in OPNsense's order) and a subclass of the pfSense reader overrides the rest; the emitter subclasses the pfSense emitter and turns its nodes into the newer models. What both get right is shared, and so is what one fixes. |
| OPNsense: rules of *Rules [new]*, for one series | The legacy rule page is a plugin in 26.7, and the newer models are where OPNsense goes. The models are not migrated on a restore, so the file has the form of the series it is for (`--target-version`): the port forwards changed in 26.1, rules for both IP versions came in 25.1, ICMPv6 types in 25.7, *received-on* in 26.7. |
| OPNsense: no categories, no interface groups written | Restoring the Categories area replaces every category of the firewall, and a rule that names a category uuid the firewall does not have shows none. As for pfSense, groups are created by hand (`INTERFACES_REQUIRED`). |
| OPNsense: the word of an interface network only where it is exact | OPNsense adds fe80::/10 to the network of an interface in a rule for IPv6. The model holds it where the source did (an OPNsense source); elsewhere the addresses are written. |
| RouterOS: `!dstnat` as allow rules for the port forwards ahead of a deny | On RouterOS a port forward needs no filter rule: the default configuration drops what comes from WAN unless destination NAT translated it. The model has no NAT state; one allow rule per destination NAT rule, for what it translates, ahead of the deny, is exact when nothing below blocks that traffic, which is checked. |
| Azure: an allow rule never says `*` | Microsoft documents `*` as TCP, UDP and ICMP, but the default DenyAll rules suggest it matches more. An allow rule names the three; a blocking rule may say `*`, which then blocks at least as much. |
| The conduit check reads the matrix | The matrix already holds what a policy can allow between zones, more where it cannot be exact and marked. Checking the model against it inherits that: a check that passes holds for the policy as read; a finding that rests on a marked part is possible, and fails the gate too. |
| A model file is checked strictly | A gate that passes because of a typo is worse than none: an unknown key, a key twice, a zone or service that cannot be read are errors. |
| The equivalence check from above and from below | Two policies are equal where what one surely allows the other cannot not allow. Each policy is a pair of sets of boxes per pair of zones; the differences of the two are exact where both are read exactly, and possible elsewhere, never left out. |
| Labels for what the sets do not hold | Applications, users, categories, schedules, and objects and rules both policies hold alike but that cannot be read, are labels of a connection. Comparing per combination makes identical policies equal whatever such an object holds, and a change of one rule a difference of that rule. A difference is certain only where it holds whatever the multi-valued labels are, since a connection carries some of them, which is not known. |
| `convert --compare` reads the output back | The emitter's copy of the model says what it meant to write; FWShift's own parser of the target says what was written. Reading back checks the emitter end to end, for the eleven targets FWShift reads. |
| iptables: lists become chains | iptables has no objects and a rule matches one address per side. A chain per list keeps a rule with long or negated lists to one jump, instead of a product of lines. |
| Check Point input is API JSON | There is no configuration file. The API export is documented, versioned and what other tools consume. |
| Check Point output is a `mgmt_cli` script that stops at the first error and never publishes | The session is the unit of change on a management server: a person reviews it in SmartConsole and publishes or discards. A script that carried on after a refused call would leave a policy with rules missing. |
| Check Point: one inline layer per zone pair | A cell that holds a zone and an address means "either". Zone and address on one side need two rules in sequence, and a layer per rule would swallow the traffic that the rule does not match. A layer per zone pair holds every rule for that pair. Rules whose cells can carry the zone stay single rules. |
| Check Point: explicit cleanup in every layer written | The implicit cleanup action is a property of the layer that the script does not control. |
| ASA: only bound access lists, and permit entries get destination zones | An ASA has dozens of lists that are not policy; `access-group` says which are. "Permit to any" on an ASA never means "back out of the same interface", so the model must not say it either: the zones an entry can reach are written out, narrowed by routes where the entry names addresses. |
| ASA output: a list per zone plus a global list that ends the policy | The lists an ASA reads first are per interface. A rule for every zone above a rule of one zone is repeated in that zone's list to keep the order. Binding a global list that ends in a deny is what makes sure that no interface falls back to the security-level permit. |
| ASA output: a rule that needs the outgoing interface is inactive unless networks are given | An entry cannot name it. Written without it, an allow to "any address in zone B" allows every zone. `--zone-network` lets the user say what lies behind a zone; then the networks of the other zones can be left out of the destination, by longest prefix like a route. Nothing is assumed about a zone or an address the user did not mention: such a rule stays inactive, and of an address nobody placed a permit keeps clear and a deny does not. |
| ASA output: twice NAT for every rule, destination translations `unidirectional` | One line per rule keeps the order of the model. A static rule of an ASA works both ways; the model's destination translation does not. A combining published port is written from the server side because that is the form an ASA combines with source NAT. |
| NAT order is reported, not emulated | A first-match NAT rulebase and two NAT tables differ in ways `PREROUTING` cannot express (it does not know the outgoing interface). The report names each rule that changes meaning. |
| Reserved names are renamed | An object called `all` or `HTTP` from another platform would otherwise redefine a FortiOS built-in. |
| Audit: a rule is called dead only when that is proven, and unknowns count against the claim | The finding has an action, `disable`, that people will use without reading each rule. A wrong "redundant" removes a rule that was needed; a missed one costs nothing. |
| Audit: `reorder` is carried out but always needs review | Moving a shadowed rule up flips verdicts, and which of the two rules was the mistake is not in the configuration. The tool can do the edit; it cannot make the decision. |
| Audit after a conversion works on the model, not on the output read back | Two of the six targets have no parser for what is written (PAN-OS `set` commands, the Check Point script), and what is read back is not always what was meant (a Sophos NAT rule names interfaces, not zones). It shows what the conversion knows it changed, which is where a lost deny rule shows. |
| Sophos: a rule with exclusions of N kinds becomes N rules | Exclusions are one condition for the whole rule ("skip where all of them hold"); the model negates per field. "Not (A and B)" is "not A, or not B": two rules, each with one field cut down, say exactly that, and every target can write them. |
| Sophos output: of several negated fields, all but one are written as address ranges | The other way round. Two exclusions would skip the rule only where both hold, which is a wider rule than the source had. A complement of addresses is exact; a host name has none, and then the rule is disabled. |
| Sophos output: zones are not written | A zone entity carries the device access of the zone (which services of the firewall itself answer there). An import overwrites what has the same name: writing `LAN` would change who can reach the admin console. |
| Sophos output: every rule stands after the one before it | With `Bottom` for each, the order would hang on the order in which the firewall takes the entities, and a rule it does not take would let the rules after it move up. |
| Sophos output: a placeholder is a host name under `.invalid` | It has to be an object every firewall takes and that matches nothing; `0.0.0.0` may be refused, and a refused entity can end an import. A name under `.invalid` never resolves. |
| Cisco Secure Firewall: two formats, `fmc` and `fdm`, one parser and one emitter | The two managers hold the same policy for the same device in two shapes of JSON (CamelCase types with `objects`/`literals`, lower-case types with plain lists and wrappers). What a rule means, how NAT is ordered and what an object can say is the same; a second parser would repeat all of it. |
| Management Center input is REST API JSON | There is no configuration file a person can export and read: the `.sfo` of Import/Export is a binary archive. The API is documented, and its answers are what Cisco's own tooling reads. |
| Management Center output is a script that calls the API, and carries the policy as data | The API is the only way in. A list of `curl` calls cannot be written ahead of time: every reference needs the id the Management Center gave the object when it was created. So the output is a program that creates, remembers ids and goes on, and the policy it creates is data at its end, which a person (and a test) can read without running anything. |
| The script creates new policies and changes nothing that exists | A Management Center has no session to review and discard, as a Check Point server has. What can be offered instead is a run that looks before it creates anything, refuses to touch a name that is taken, assigns nothing to a device, writes down what it created, and can delete it again. |
| The loader is a file of its own that imports nothing of the package | It runs on another machine, long after the conversion, and has to be readable as what it is: 700 lines that talk to a firewall manager with someone's password. It is tested as a module and shipped as text. |
| Prefilter rules are read as the first rules of the policy | They are evaluated first, and Fastpath and Block are final. Analyze is the one thing a single list cannot say: "the rules below me in this list do not get this traffic, the next list does". A Fastpath rule below an overlapping Analyze rule is therefore not converted, and a Block rule in that place is reported. |
| A Device Manager gets no disabled rules and no placeholders | It has no rule that is switched off, and an import that is refused half way is worse than a shorter file. What cannot be written is left out and listed as skipped, with the warning for blocking rules. |
| A file for a Device Manager holds no zones | An import replaces what has the same name: a zone written without its interfaces would take them out of the zone the device has. |
| Access rules of a Cisco source keep their real addresses until an emitter needs otherwise | As for an ASA: the parser rewrites the rules for the model (pre-NAT), and the Cisco emitters turn that round again for the NAT rules that are really written. |
| Terraform input becomes the answers of the cloud's CLI | What a security group or a network security group decides does not change with the tool that made it. Turning the resources into the answers the AWS and Azure parsers read keeps one reading of each cloud, with its reviews and judges; what is Terraform's own (echoes, plans, unknowns) stays in one file. |
| Terraform: what a plan does not know is worked out from the configuration, or not converted | An id that is not known yet still names one resource, and the configuration says which: the address stands for it, and two references to it agree. Anything else (a variable, a data source, a dynamic block) could be any value, so what holds it is not converted rather than guessed. |
| Terraform: a separate rule resource wins over the inline copy of it | After a refresh both say the same; where they differ, the state is stale, and the separate resource is what Terraform will make true. Said, not silently chosen. |
| Terraform output is plain HCL for a root module, new resources only | An apply then fails on a name that exists instead of adopting or replacing it (AWS refuses a duplicate group; azurerm a resource it does not manage). Attaching the groups is a change to resources the output does not know, as for the CLI targets. |
| Google Cloud: one list without zones, egress and ingress composed between instances | A connection between two instances passes the egress rules of the sender and the ingress rules of the receiver, each list with its own steps. The model has one first-match list: from outside the ingress rules, to outside the egress rules, and between instances the egress rules that deny, then for each that allows the ingress rules cut to it, as for AWS and Azure. |
| Google Cloud: `goto_next` becomes the rules below it without what it matches | It leaves the policy for the next step, which in one list is "the rules after this policy". Subtracting its match from the rules below it in the same policy says exactly that; when that cannot be worked out, the rules after it are not converted. |
| Google Cloud output is a new global policy, associated with nothing | Creating it changes no traffic; associating it, and putting it before the VPC rules, are two changes a person makes after reading the report. Each rule is written for ingress and egress, so a connection between instances meets the model's verdict at both ends. |
| Meraki: the answers of the Dashboard API, in one file | The configuration of an MX is spread over a dozen endpoints of the network and its organization; one JSON file of them under their names (the jq command of the manual) is what FWShift reads. The outbound table alone is read too, with what it cannot know said. |
| Meraki: a zone per VLAN, and the internet | The MX names addresses, not zones. A VLAN with the subnets of its static routes is the zone a packet comes from; traffic inside one VLAN does not pass the MX and is allowed in the model. |
| Meraki output: from the internet only NAT, with allowed remote addresses that never let in more | An MX lets traffic from the internet in only by its NAT rules, whose allowed remote addresses are a list of sources with no order and no deny. The rules of the model that allow all of a NAT rule's traffic give their sources (kept to their zones outside); a rule that blocks some of it first ends the list, and one that cannot be written is left out, so what is written is never more than the model allows; the tests check that packet by packet. |
| Stormshield: the configuration files, read with a grammar of what is known; anything else not converted | The syntax of a rule line in a slot file is not published. The reader takes what Stormshield's own tools and their test data show (action, options, `from ... on ... to ... on ... port ...`, comments) and makes any other word, an empty name or a word twice a reason not to convert the rule. A backup (`.na`) is encrypted with AES, which the standard library does not have: it is refused with the `decbackup` command. |
| Stormshield: the global policy, then the local one, as one list | A global `deleg` of everything at its end hands the rest to the local policy, which is what one list of rules says; a `deleg` with conditions cannot be said so and is refused. `decrypt` and `log` go on to the next rule and are left out. |
| Stormshield output: a serverd script for one slot, not made active | Serverd commands are documented and checked by the firewall one by one; slot files have no published syntax. A rule of SNS has one IP protocol, so a rule of the model becomes one per kind of service and per pair of interfaces, which together match what it matches. |
| Huawei: the implicit permit inside a zone is an explicit rule at the end | The model has one default for what no rule matches; a USG denies between zones and passes inside one (unless `default packet-filter intrazone enable`). A rule of scope intrazone at the end keeps both. |
| Huawei: the model names addresses as they arrive; `nat server` is undone on reading and redone on writing | `nat server` is done before the security policy, whose rules name the inside address, as on FortiOS: the parser rewrites destinations to the pre-NAT address, the emitter back, for the translations it writes. A translation a `nat server` cannot say (a source, a destination zone, several source zones, a service it cannot read, an exemption above it) is not written, and the rules are left as the model names them. |
| Huawei: lines by indent and by the `#` lines between blocks | VRP prints the commands of the system view with one space and puts `#` between blocks. A line after a `#` line is a command of the system view, `nat server` always is, and every line of a rule stays in its policy; what must not be missed (`default packet-filter intrazone enable`) is looked for at every depth. |
| Huawei output: zones listed, never left out; rules that cannot be said written `disable` first | A rule without zones matches traffic to the firewall itself as well; commands take effect when they are entered, so a rule that is to be disabled is disabled before it has conditions, and a side it cannot say gets an address no forwarded packet has. |
| IOS: the zones are the zone-based firewall's, or the interfaces; lists composed per pair of zones | A connection meets up to three lists (inbound, outbound, zone pair), each first match. Where only inbound lists decide, each stays the rules of its zone, as written; otherwise the three are composed for each pair of zones, as AWS and Azure lists are, with what an entry above already takes left out. Interfaces of one zone with different lists are zones of their own. |
| IOS: the model names addresses as they arrive; outbound lists and the zone-based firewall are rewritten through NAT | An inbound list sees the packet before NAT, an outbound list after it, and the zone-based firewall is read as seeing inside addresses. Rewriting their entries through the static translations and the port translation of a list of sources gives one address space; NAT that is not read makes the entries it could change not converted. |
| IOS output is the zone-based firewall, with the zone membership as comments | Interface access lists are stateless and need rules for the replies; inspection is stateful, as the model is. Creating zones, lists and policies changes nothing; putting an interface in a zone does, so it is left to a person, as are the NAT lines. |
| Standard library only | Runs on a bare RHEL box and is easy to audit. |
| GPL-3.0-or-later | Copyleft: changes to a tool that rewrites security policy stay open to inspection. |

## Vendor behaviour the code relies on

These come from documentation and community knowledge, not from a lab. Each
needs confirming on a device, and each is a place to look first if a converted
policy behaves unexpectedly.

| Assumption | Used in |
|---|---|
| FortiOS looks policies up after destination NAT; with central NAT the policy names the mapped address and VIPs cannot be used in policies | `rewrite_destinations`, FortiOS emitter |
| With per-policy NAT a FortiOS policy naming the mapped address also matches VIP traffic | FortiOS parser |
| A FortiOS deny policy matches VIP traffic only with `match-vip enable` (default from 7.2.3) | `_deny_and_vips` |
| FortiOS `all` is IPv4-only; `srcaddr6`/`dstaddr6` must both be set for IPv6 to match | FortiOS parser and emitter |
| FortiOS has `srcaddr6-negate` / `dstaddr6-negate` and `address6` of type `fqdn` | FortiOS emitter |
| A FortiOS zone can be created without interfaces | FortiOS emitter |
| PAN-OS negation and FQDN objects cover both IP versions | PAN-OS emitter, FortiOS parser |
| PAN-OS accepts `0.0.0.0/32` as an address, a bare `set tag NAME`, FQDN objects as NAT match, and a service group in a NAT rule | PAN-OS emitter |
| The App-ID names in `appmap.py` (`ping`, `icmp`, `gre`, `ipsec-esp`, ...) | PAN-OS emitter |
| A PAN-OS NAT rule needs one destination zone; `any` is not accepted | PAN-OS emitter (`--target-nat-zone`) |
| iptables NAT: `FORWARD` sees destinations after `PREROUTING`; `POSTROUTING` cannot match the input interface; `iptables-restore --noflush` adds to existing chains. (The filter-table syntax and semantics the emitter and parser rely on are checked against a kernel, see Testing.) | iptables parser and emitter |
| nftables: every base chain at a hook sees a packet in the order of its priority, whatever table; accept ends one base chain, drop is final; a family without a base chain is not filtered; the forward hook sees addresses after prerouting DNAT. (Checked against the kernel, see Testing.) Printed forms of nft 0.9.3 to 1.1.6 taken from their sources | nftables parser and emitter |
| NSX: categories run in a fixed order (Ethernet, Emergency, Infrastructure, Environment, Application), policies by sequence number with the default policy last, rules by sequence number; `JUMP_TO_APPLICATION` skips the rest of Environment; the default layer-3 rule decides what no rule matches; a connection is checked at both ends (applied-to); a segment in a group means its workloads. From the Policy API reference, the SDK schema and the Terraform provider, not from a manager | NSX parser and emitter |
| AWS: a group allows only; the rules of the groups of an interface are one set; a reference to a group means the private addresses of its interfaces; a connection inside the VPC needs the source's outbound and the destination's inbound rules; a network ACL is first match by rule number, ends in `*` deny, is stateless and not applied inside a subnet; the internet gateway translates public addresses for what comes from outside. From the botocore service model and the VPC and EC2 user guides, not from an account | AWS parser and emitter |
| Azure: a group's two lists are first match by priority (100 to 4096), each ending in three default rules (65000 to 65500); traffic between two groups passes the outbound list of the source's and the inbound list of the destination's; the groups are stateful; `VirtualNetwork` is the virtual network, its peerings and what gateways connect; `AzureLoadBalancer` is 168.63.129.16; `*` is TCP, UDP and ICMP; an interface behind a group of its own and one on its subnet passes both; 2,000 rules and 100 application security groups per group. From the REST API specifications, the Azure CLI and its test recordings, and the documentation, not from a subscription | Azure parser and emitter |
| RouterOS: rules first match within a chain; a built-in chain accepts what no rule decides (that cannot be changed); falling off a custom chain returns to the caller; `forward` sees the destination after `dstnat` and the source before `srcnat`; the two NAT chains apply independently; `connection-nat-state=!dstnat` is what `dstnat` did not translate; an export omits interfaces with default settings and dynamic entries; a backslash at the end of a line continues it, inside quoted strings too, with `\_` for a space; `:if` and `:error` stop an import. From MikroTik's documentation (read through summaries), the schemas of the community.routeros collection and the Terraform provider, and published exports, not from a router | RouterOS parser and emitter |
| RouterOS, assumed: `icmp-options=TYPE:0-255` is every code; `dst-port` lists of up to 15 entries; `src-address-list=!name` without quotes; `reject-with=tcp-reset` only where the rule is TCP; protocol numbers of names other than the well-known ones; that an address list entry with a DNS name exports as the name | RouterOS parser and emitter |
| Check Point matches the access rulebase on the original packet and takes the destination zone after NAT | model, Check Point parser and emitter |
| A connection sent into an inline layer never returns to the parent layer; a layer without a matching rule applies its implicit cleanup action | Check Point parser |
| An object with automatic static NAT matches its translated address in the rulebase; with manual NAT the rules name the original address | `_automatic_nat`, `_also_valid` |
| Automatic NAT rules in `show nat-rulebase` name the object itself in the translated column; the address is in the object's `nat-settings` | `_nat_rule` |
| Shape of `show access-rulebase` / `show nat-rulebase` answers: `rulebase`, `objects-dictionary`, sections, `from`/`to`/`total` (with `total` counting rules, not section titles), `inline-layer`, the field names of each object type; objects of data domains are predefined | Check Point parser |
| `mgmt_cli` syntax of every call the script makes (`add host`, `add network`, `add address-range`, `add dns-domain`, `add group`, `add service-tcp/-udp/-sctp/-icmp/-icmp6/-other`, `add service-group`, `add security-zone`, `add access-layer ... add-default-rule false`, `add access-rule ... position N`, `add nat-rule ... position bottom`), switches after the command, a non-zero exit status when the server refuses a call | Check Point emitter |
| Check Point accepts an address range `0.0.0.0`-`255.255.255.255`, domain objects as group members, empty groups as placeholders, and object names made of letters, digits, `.`, `_` and `-` | Check Point emitter |
| Meraki, all rows below: from the OpenAPI specification of the Dashboard API (v1), Meraki's knowledge base and developer documentation, the Python SDK, the Terraform provider, the Ansible collection and Meraki's published backup and import scripts, read and never run; no call was made to a Dashboard | Meraki parser and emitter |
| The outbound table first match from the LAN, ending in a fixed default rule that allows; layer 7 rules block after it; traffic inside one VLAN does not pass the MX; from the internet only NAT (its allowed remote addresses), or with NAT off on an uplink and in passthrough mode the inbound table | Meraki parser and emitter |
| Answers: `l3FirewallRules`, `inboundFirewallRules`, `l7FirewallRules`, `portForwardingRules`, `oneToOneNatRules`, `oneToManyNatRules`, `vlans`, `singleLan`, `staticRoutes`, `policyObjects`, `policyObjectsGroups`, `uplinkStatuses`, `uplinksNat`, `applianceSettings`; the GET of a rule table ends in the Default rule, which a PUT must not hold | Meraki parser and emitter |
| Assumed, not documented: the inbound table decides traffic NAT lets in when NAT is off on an uplink; layer 7 rules of ports and address ranges act on the LAN's traffic only; `VLAN(n).*` holds the IPv6 prefixes of the VLAN; the uplink `both` is every uplink; `allowedIps` of `any` or a list of networks; puts of more than about 900 rules time out | Meraki parser and emitter |
| Stormshield, all rows below: from Stormshield's documentation (the serverd command reference for v4 and v5, the user manual, the technical note on the command line, the ANSSI recommendations), its Python API client and Ansible playbooks with their test data, and published readers of its files (snspoliciestocsv, decbackup-py, the CrowdSec bouncer), read and never run; nothing was run on a firewall | Stormshield parser and emitter |
| Filter rules first match, on the addresses before NAT; implicit rules first, then the global policy, then the local one; what no rule matches is blocked without a log; `decrypt` and `log` go on | Stormshield parser and emitter |
| ConfigFiles: `network`, `object` (`[Host]`, `[Network]`, `[Service]`, `[Protocol]`, `[Fqdn]`, `[Internet]`), `objectgroup`, `servicegroup`, `Filter/slotinfo` and `Filter/NN` with `[Filter]` and `[NAT]` | Stormshield parser |
| Serverd: `CONFIG OBJECT ... NEW ... update=1`, `CONFIG FILTER RULE INSERT` with the tokens of `RULE UPDATE`, `RULE REMOVE ... position=all`, `CONFIG FILTER ACTIVATE`, `CONFIG SLOT UPDATE` | Stormshield emitter |
| Assumed, not documented: the syntax of a rule line beyond the forms shown; that `!` negates the whole list; `on` after the destination for the outgoing interface; the layout of `slotinfo`; `ipv6=` and `prefixlenv6=` on the commands that create objects; `port=0` in a service | Stormshield parser and emitter |
| Huawei, all rows below: from Huawei's documentation and support pages for USG6000, USG6000E and USG9500 (V500, V600: security policies, address and service sets, NAT server, NAT policies, security zones, the default packet filter) and the configurations shown in them; the HedEx command reference could not be read; nothing was run on a firewall | Huawei parser and emitter |
| Rules first match; conditions ANDed, values of one condition ORed; a condition that is not given is any; `*-address-exclude` takes addresses out; `default action` deny unless permit; inside a zone permit unless `default packet-filter intrazone enable` (V100R001: the default policy) | Huawei parser and emitter |
| `nat server` before the security policy (rules name the inside address and port), `nat-policy` after it; `zone` limits a `nat server` to traffic from that zone; without a protocol it translates both ways unless `no-reverse`; display adds an id after the name | Huawei parser and emitter |
| Address entries: `A mask LEN|DOTTED`, `A LEN`, `A WILDCARD` (no `mask`), `range A B`, `address-set X`; service entries `protocol P source-port .. destination-port P [to Q] ...`, `icmp-type T [C]` | Huawei parser and emitter |
| Assumed, not documented: the indentation of display output; the ports of the predefined services; the form of IPv6 entries in address sets on input; that `disable` is accepted in a new rule; that rule groups are read in order | Huawei parser and emitter |
| IOS, all rows below: from Cisco's IOS 12.2/15 command references and configuration guides (IP access lists, object groups, sequence numbers, IPv6 access lists, the zone-based policy firewall, Port-to-Application Mapping, NAT and its order of operation, document 6209), the IOS XE 17.15 YANG models, and the grammars of Batfish and Ansible cisco.ios (read, never run); nothing was run on a router | IOS parser and emitter |
| A packet from A to B: inbound list of A, NAT (outside to inside before routing, inside to outside after), outbound list of B, then the zone-based firewall; an undefined or empty list passes everything; a list with entries ends in an implicit deny; IPv6 lists end in permits of neighbour discovery and a deny | IOS parser |
| Zone-based firewall: no zone pair between two zones drops, inside one zone passes unless a zone pair from the zone to itself (15.0(1)M) says otherwise, zoned to unzoned drops, unzoned to unzoned passes, `self` is the router; `class-default` drops; `inspect` is stateful, `pass` one way; a class map's list takes what it permits | IOS parser and emitter |
| Port names per protocol (TCP 514 `cmd`, UDP 514 `syslog`); IOS writes ports as names; `sctp` only in IPv6 lists; `ahp` for AH; ICMPv6 as `icmp` with `echo-request`; object groups of networks take subnet masks, entries wildcard masks | IOS parser and emitter |
| Assumed, not documented: which addresses the zone-based firewall sees under NAT (the inside ones, after a Cisco employee's answer, disputed); that a list of remarks only is empty; that a class map without match statements matches nothing (read as not converted) | IOS parser and emitter |
| ASA: interface list, then global list, then deny; an interface without list (and no global one) permits to lower security levels; `any` is both IP versions from 9.0; access lists name real addresses and ports from 8.3. (Checked against Cisco's configuration guide in review.) | ASA parser |
| ASA never forwards back out of the arrival interface or between equal security levels unless `same-security-traffic` permits it, whatever the lists say; an FTD forwards between and within all interfaces | `_blocked`, `_place` |
| ASA picks the outgoing interface by its routing table (connected networks, static routes) for real addresses; a NAT rule does not send traffic elsewhere than the route would. (Not verified, and known to be too simple: an ASA takes the outgoing interface from the NAT rule that translates the destination unless `route-lookup` is set, so this holds where the routes agree with the NAT rules.) | `_routed`, `_egress` |
| ASA NAT: twice NAT in order, then object NAT sorted (static first, fewest real addresses, lowest address, name), then `after-auto`; one rule may translate the destination and another the source, but a twice NAT rule that names both claims the connection; `destination static <mapped> <real>`; `service <original> <translated>`; `interface` in the source is the mapped interface's address, in the destination the real interface's. (Syntax and service order checked against Cisco's guide in review.) | ASA parser, ASA emitter, `note_nat_order(whole=...)` |
| ASA: `fqdn` without `v4`/`v6` resolves IPv4; running-config always prints the `(real,mapped)` pair of a NAT rule; the port, protocol and ICMP names in `parsers/asa.py` | ASA parser |
| An ASA accepts what the emitter writes and has not been loaded anywhere: `range` objects for IPv6 and from `0.0.0.0`, `network-object ::/0`, `service 255`, host `192.0.0.8`, `lt`/`gt` in service objects used by NAT, `pat-pool` with an object group, `nat (any,any)`, `unidirectional` on `source static any any destination static`, `no-proxy-arp` with interface `any`, `fqdn v6`, names that start with a digit | ASA emitter |
| An ASA refuses a NAT rule that names one of its own interface addresses as an object (the keyword `interface` is wanted), and an object group with IPv4 and IPv6 members in NAT. (Both confirmed from Cisco sources in review.) | ASA emitter |
| Sophos: firewall rules are first match with an implicit drop, IPv4 and IPv6 in rulebases of their own; a rule matches the destination address before destination NAT and the destination zone after it. (A third-party knowledge base and a Sophos community article; not found in Sophos's own reference.) Whether the *service* of a rule is the one before or after a port translation is not known: FWShift takes the original, as the model does | Sophos parser and emitter |
| Sophos: a list that is absent is "Any" (the templates of Sophos's SDK leave the element out for Any) | Sophos parser and emitter |
| Sophos: exclusions apply together, a rule is skipped only for traffic that matches every kind of exclusion it has. (A third-party knowledge base; a community report of a Drop rule with two exclusions "not working" fits it. Not found in Sophos's documentation.) | `_exclusions`, `_variants` |
| Sophos: traffic between two interfaces of one zone needs a rule (from memory) | Sophos parser (`default_intrazone`), `INTRAZONE_ALLOW_ADDED` |
| Sophos: Security Heartbeat on a rule limits who the rule is for (not confirmed) | Sophos parser |
| Sophos NAT: one table, first match; a rule can translate source and destination; it matches original source, destination and service and the inbound and outbound interface; "Any" is the outbound interface of a rule that publishes an address; a linked rule is source NAT only, takes all criteria of its firewall rule, and an independent rule above it wins. (Sophos help and API documentation.) Not known: what an outbound interface on a destination NAT rule matches | Sophos parser and emitter |
| Sophos: the element names of a NAT rule's match, `OriginalSourceNetworks`, `OriginalDestinationNetworks` (child `Network`), `OriginalServices` (child `Service`), `InboundInterfaces` (child `Interface`). **From memory of exports.** The API page names the parameters Network, Service and Interface without their containers; `OutboundInterfaces/Interface` is read by a community script. A file that names them otherwise is not misread: an unknown element that looks like a criterion makes the NAT rule unsupported | Sophos parser and emitter |
| Sophos: the root `<Configuration APIVersion="..." IPS_CAT_VER="1">` (seen quoted from an export of 19.5 as `1905.1`; `1800.1` for 18.0 is by that pattern), entities with `transactionid=""`, IPv6 `Subnet` as a prefix length (not found), `HostType` `IPList` with `ListOfIPAddresses` and `System Host` (API documentation) | Sophos parser and emitter |
| Sophos services: ICMP types and codes as numbers, -1 for any, from the lists of the API page (the web console shows names; both are read); IP protocols by the keyword of the IANA registry, of which the API page shows some (`HOPOPT`, `IPv6-ICMP`, `OSPFIGP`, `IPProto143` to `IPProto255`); port 0 is not taken | `appmap.py`, Sophos emitter |
| Sophos names: 60 characters for a host or rule, 50 for a service, no comma (API documentation). Whether names differ by case is not known: names of another platform are kept apart whatever their case. The list of services a firewall comes with (`SOPHOS_FACTORY_SERVICE_NAMES`) is from memory and not complete | `names.py`, Sophos emitter |
| Sophos import: takes a `.tar` that holds `Entities.xml`, of its own version or an older one; overwrites entities of the same name; can stop at an entity it does not take (a community log shows "IMPORT Failed ... Exiting"; another source describes other settings still being imported). What the web console says then is not known | Sophos emitter, manual |
| A Sophos Firewall accepts what the emitter writes and has not been imported anywhere: an FQDN host under `.invalid`, IP ranges as what a NAT rule translates to, `Position` `After` with an anchor of the same IP version, `NATMethod` `OnetoOne` and `Round-robin` as written, rule names with spaces, a firewall rule without `WebFilter` and the other policy elements | Sophos emitter |
| Management Center, access control: rules are first match; mandatory rules before default rules; with inheritance the mandatory rules of the parent, then the child, then the default rules of the child, then of the parent; the default action of the policy applies last; *Monitor* decides nothing; *Trust* allows without inspection; the access rules see the real (translated) destination. (Configuration guide; not run.) | Cisco parser, `Lab` of the tests |
| Management Center, prefilter: evaluated before the access rules; *Fastpath* and *Block* are final, *Analyze* hands the traffic to the access rules **and ends the prefilter for it** (the first matching prefilter rule decides); tunnel rules match the outer packet of GRE, IP in IP, IPv6 in IP and Teredo (UDP 3544); the default action is "analyze all tunnel traffic" or "block all tunnel traffic". (Configuration guide.) | Cisco parser |
| Management Center REST API, as read: object types `Host`, `Network`, `Range`, `FQDN`, `NetworkGroup` (`objects` and `literals`), `ProtocolPortObject` (`protocol`, `port`), `ICMPV4Object`/`ICMPV6Object` (`icmpType`, `code`; **without `icmpType`: every type**, an inference), `PortObjectGroup`, `SecurityZone`, `InterfaceGroup`; `AccessRule` with `sourceZones`, `destinationZones`, `sourceNetworks`, `destinationNetworks`, `sourcePorts`, `destinationPorts` (each `objects`/`literals`), `action`, `enabled`, `logBegin`, `logEnd`, `metadata.ruleIndex`, `metadata.section`, `metadata.accessPolicy`; lists with `items` and `paging.count`; names and ids only without `expanded=true`. (API documentation, the Python client `fmcapi`, the Terraform providers. Field by field, not from an answer of a real server.) | Cisco parser, `fmc_sample.json` |
| Management Center, where a policy says it inherits: an `AccessPolicyInheritanceSetting` with `basePolicy` (a call of its own, `policy/accesspolicies/{id}/inheritancesettings`; a community post shows it with the id of the policy), or `metadata.inherit` and `metadata.parentPolicy` on the access policy (**not confirmed**, from tooling), or rules in the list of the policy that name another policy in `metadata.accessPolicy` (a community post reports that the list of a child holds the rules it inherits; whether those rules name the parent there is not known). Where none of the three is in the input, the policy is read without a parent and the report says that it is not known whether it has one (`INHERITANCE_UNKNOWN`). | `_inheritance` |
| Management Center, `PrefilterRule`: `ruleType` `PREFILTER` or `TUNNEL`, `action` `FASTPATH`/`BLOCK`/`ANALYZE`, `sourceInterfaces`/`destinationInterfaces`, `encapsulationPorts` (`GRE`, `IP_IN_IP`, `IPV6_IN_IP`, `TEREDO`), `bidirectional`, `tunnelZone`; `PrefilterPolicy.defaultAction.action` `ANALYZE_TUNNELS`/`BLOCK_TUNNELS`; the access policy names its prefilter policy in `prefilterPolicySetting`. (API reference and the Terraform provider.) | `_prefilter` |
| Management Center NAT: `FTDManualNatRule` and `FTDAutoNatRule` with the fields of the ASA `nat` command (`originalSource`, `translatedSource`, `originalDestination`, `translatedDestination`, the four port fields, `interfaceInTranslatedSource`, `interfaceInOriginalDestination`, `unidirectional`, `patOptions`, `dns`, `noProxyArp`, `routeLookup`, `fallThrough`); manual rules in `metadata.section` `BEFORE_AUTO`/`AFTER_AUTO` with `metadata.index`; automatic rules sorted by the device as on an ASA. `sourceInterface`/`destinationInterface` name a security zone or an interface group. (`fmcapi`, Terraform provider.) | `_nat`, `_manual`, `_automatic` |
| Device Manager, as read: the export is a JSON list, first a `metadata` object (`hardwareModel`, `softwareVersion`, `apiVersion`, `configType`, `exportType`), then `identitywrapper` objects with `data`, `action` and, for a rule, `parentName` and `index`; types `networkobject` (`subType` `HOST`/`NETWORK`/`RANGE`/`FQDN`), `networkobjectgroup`, `tcpportobject`, `udpportobject`, `protocolobject`, `icmpv4portobject`, `icmpv6portobject`, `portobjectgroup`, `securityzone`, `accessrule` (`ruleAction` `PERMIT`/`TRUST`/`DENY`, `eventLogAction`), `manualnatrule`, `objectnatrule`. (The import/export chapter of the API guide and the API specification that ships with Cisco's Ansible modules.) | Cisco parser, `fdm_sample.txt` |
| Device Manager: the names of its protocols (`GRE`, `ESP`, `OSPFIGP`, ... 121 of them, none for protocols 4 and 41) and of its ICMP types and codes (`ECHO_REQUEST`, `DESTINATION_UNREACHABLE`/`PORT_UNREACHABLE`, ...), and **which number each stands for**. The names are from the API specification; the numbers are those of the IANA registries for the same keywords, which the specification does not give. A wrong pair would read or write another protocol than was meant. | `appmap.py` (`FDM_PROTOCOLS`, `FDM_ICMP_TYPES`, ...) |
| Device Manager: the containers of its NAT rules are called `NGFW-Before-Auto-NAT-Policy`, `NGFW-After-Auto-NAT-Policy` and `NGFW-Object-NAT-Policy`, its access policy `NGFW-Access-Policy`; a manual rule is "after auto" when its container says `afterAuto`. **The first name is what the emitter writes as `parentName`**; if a device calls it otherwise, the import of the NAT rules fails. (Seen in examples of the API guide; not on a device.) | Cisco parser and emitter |
| Device Manager import: takes a text file or a zip of one; wants `hardwareModel` and `softwareVersion` of the target in the first object; `apiVersion` may be `latest`; `configType` `DELTA_CONFIG` and `exportType` `PARTIAL_EXPORT` are right for a file that adds; an object without `id` and `version` and with `action` `CREATE` is created, or replaces what has its name; **references are resolved by type and name**; an access rule without `parentName` goes to the one access policy, and one without `index` to the end of its rules; nothing is deployed unless `autoDeploy` says so. (API guide, import/export chapter, where the reviewer of round 15 found each of these stated, except two: that the model and the version are wanted for a file that only adds (the guide says it for a full import), and where manual NAT rules without an index land.) | `as_fdm` |
| Device Manager: an access rule cannot be disabled (no `enabled` field in the specification); it has no description; a NAT rule can (`enabled`). Interfaces in a NAT rule are referred to with their own type (`physicalinterface`, `subinterface`, ...), which the emitter cannot know and writes as `physicalinterface`. | Cisco emitter (`DISABLED_RULE`, `INTERFACES_REQUIRED`) |
| Both managers: a network group holds no FQDN object; a port group holds port objects and no group; source and destination ports of a rule are of one protocol; a rule that blocks cannot log at the end of a connection; object names take letters, digits, `.`, `_`, `-` up to 64 characters (rule names 50 on a Management Center, with spaces); names are compared without case. (Configuration guides for the first four; the name rules are **conservative guesses**: the managers take more. A name FWShift makes up, and a name from another platform, is never one they would refuse by these rules; a name read from a manager of the same kind is written back as it was.) | Cisco emitter, `names.py`, `helpers.CiscoConfig` |
| Both managers come with `any-ipv4` (0.0.0.0/0) and `any-ipv6` (::/0), and the reader knows them without their being in the input. The value of the object `any` is **not** assumed. The other predefined objects whose names are avoided when writing (`IPv4-Private-10.0.0.0-8`, `HTTP`, `HTTPS`, `SSH`, `DNS_over_UDP`, ...) are a list from documentation and screenshots; a Management Center is asked for its names before anything is created, a Device Manager is not. | `_EVERY_ADDRESS`, `_SYSTEM_NETWORKS`, `_SYSTEM_PORTS` |
| Management Center REST API, as the script uses it: `POST /api/fmc_platform/v1/auth/generatetoken` with basic authentication answers with `X-auth-access-token`, `DOMAIN_UUID` and `DOMAINS`; lists take `limit` (1000 at most) and `offset` and say `paging.count`; `POST <collection>?bulk=true` takes a list (1000 items, 2 MB) and answers with the created `items`; **`POST .../accessrules?bulk=true&section=mandatory` appends in the order of the list, and a second call below the first**; `POST .../manualnatrules?bulk=true&section=before_auto` likewise; **a list of the rules gives them in the order of the policy**, with their names also when it is not expanded; 429 with `Retry-After` when asked too often, 401 when the token ran out; `DELETE <collection>/<id>`; a new `AccessPolicy` takes `defaultAction.action` `BLOCK`; a `SecurityZone` takes `interfaceMode` `ROUTED` and no interfaces. a redirect is never the right answer to an API call. (API documentation and `fmcapi`. The order of bulk-created rules is the assumption everything hangs on: if a Management Center orders them otherwise, the policy is not the policy that was converted. The script lists the rules after it created them and stops when their number or their order is not what it sent, which finds a wrong order as long as the list itself is in the order of the policy.) Object and zone names are compared without case, and zones share their names with interface groups: both are the cautious reading, neither is confirmed. | `fmc_loader.py`, `FakeFmc` of the tests |
| A manager accepts what the emitter writes and has not been loaded anywhere: host `192.0.0.8` as a placeholder, ranges from `0.0.0.0`, a `PortLiteral` with only a protocol number in a rule, `ICMPV4Object` with `icmpType` and `code` as strings, a NAT rule with `any-ipv4` as original and translated source, a PAT pool that is a network group of ranges, `newComments` on a rule that is created, `sendEventsToFMC` with `logBegin`. | Cisco emitter |
| FTD: the device shows its access rules as `access-list CSM_FW_ACL_ advanced` with `ifc`, `rule-id` and remarks `rule-id N: L4 RULE: name` / `L7 RULE: name`; an L7 rule appears as `permit` whatever its action. From documentation and memory, no device output was available | ASA parser |
| pfSense, all rows below: read in its source code (`filter.inc`, `util.inc`, `interfaces.inc`, `pfsense-utils.inc`, `diag_backup.php` and the edit pages) of RELENG_2_6_0 (config 22.2), RELENG_2_7_2 (23.3) and the development branch (config 24.5, commit 9363ac5); nothing was run, no pf ruleset was loaded | pfSense parser and emitter |
| pfSense: interface rules are `quick` on arrival; the order is floating rules, then interface groups (and l2tp, pppoe, enc0, openvpn), then the interface; non-quick floating rules decide where nothing matched, the last one; groups that share an interface are evaluated in the order of the file up to 2.7.2 and group by group later (config version above 23.3; whether 2.8.0 is "later" is not checked) | `_ordered`, `RULE_ORDER_VERSION` |
| pfSense: an `out` rule is evaluated on egress after rdr and outbound NAT; pass out is the default; `rdr pass` skips the in rules (and *Block private networks*), not the out rules | `_leaving`, `_pass_rule`, emitter `_floating_block` |
| pfSense: *Block private networks* drops 10/8, 127/8, 172.16/12, 192.168/16 and fc00::/7 before the rules; without `ipv6allow` all IPv6 is dropped; a rule without `ipprotocol` is IPv4; a type it does not know is `pass`; types and families are case-sensitive | pfSense parser |
| pfSense: a port is a number, a range or a port alias; a service name is looked up by `getservbyname` (the table in the parser has the IANA numbers of the names a FreeBSD `/etc/services` has, as far as known: not checked against one); a protocol and no port is every port, a port and no protocol is `proto tcp`; a range that runs backwards matches nothing | `_ports`, `SERVICE_PORTS` |
| pfSense: the network of an interface includes its virtual IPs (also an IP alias on a CARP address, `_vip<uniqid>`); from config 24.0 on it is one table for both IP versions, earlier a list, of which "not" is every address in pf when it has more than one entry (2.6; 2.7.2 for IPv6 of WAN and LAN) | `_network`, `NEGATED_LIST` |
| pfSense NAT: rdr before binat for what arrives, binat before nat for what leaves; a port forward with a numeric local port and several ports maps all of them to that port; NAT reflection in pure NAT mode puts the forward on the interfaces without a gateway (an `ovpn*` or `ipsec*` device counts as one with a gateway); automatic outbound NAT translates what leaves an interface with a gateway from the networks of the others, static routes over them, OpenVPN tunnel networks and the IPsec mobile pool; an outbound NAT rule without family and addresses is written for IPv4 and IPv6; `opt` in the source of an outbound NAT rule is read as an interface name | pfSense parser and emitter |
| pfSense restore of an area: the file may have the root `<pfsense>`; the whole section is replaced; an empty or missing section is refused; no version check and no upgrade; the filter reloads by itself; separators, `bypassstaticroutes` and linked rules go with the section | emitter, `PFSENSE_RESTORE`, manual |
| pfSense XML: a flag is an element, empty or not; text is decoded twice (also inside CDATA); alias names are up to 31 of `[A-Za-z0-9_]`, not a word of pf or of pfSense; descriptions take any text. A pfSense accepts what the emitter writes and has not restored it anywhere: trackers from 2000000001, `associated-rule-id` empty, `natreflection` `disable`, outbound NAT in the form of config 23.x | emitter |
| OPNsense, all rows below: read in its source code of 24.7, 25.1, 25.7, 26.1 and 26.7 (`filter.inc`, `filter.lib.inc`, `diag_backup.php`, the models `Firewall/Filter`, `Alias`, `DNat`, `Category`, `Group`, and the classes `Rule`, `FilterRule`, `ForwardRule`, `SNatRule`, `DNatRule`), not on a running OPNsense | parser and emitter |
| OPNsense flags: legacy `disabled`, `log`, `interfacenot`, outbound `nonat`/`staticnatport`, port forward `disabled`/`nordr` are `!empty()`; legacy `quick` absent means quick unless floating; source/destination `not` is `isset` up to 25.7, `!empty()` from 26.1; `blockpriv`/`blockbogons` `isset` in 24.7 and 25.1, `empty()` from 25.7; a BooleanField of the newer models is `1` true, `0` or empty false | `_Normalizer`, `_bool` |
| OPNsense order: floating 200000, group rules 300000 + the sequence of the group (the newer kind for the groups of the system, OpenVPN and WireGuard, at 0), interface rules 400000, rules port forwards register 500000; inside one value the newer kind first by sequence, then the old kind in file order; any rule can be non-quick and (on a tab) for out or both directions | `_Normalizer._filter`, `_ordered` |
| OPNsense rules: no `ipprotocol` in a legacy rule is one rule for both families; `inet46` is split in two before addresses are mapped, and an interface network in the IPv6 half gets `,fe80::/10` (a comma list becomes a rule per item, `!` applies to the first); ports only for TCP, UDP and TCP/UDP; `(device)` without an address of a family matches nothing of it | `_network`, `rule_family` |
| OPNsense aliases: content one entry per line; a table is the union of the entries of the alias and of every alias it holds, `!` entries included, longest prefix decides; a disabled alias is an empty table; a disabled port alias inside another adds nothing | `_aliases`, `_flat`, `_effective` |
| OPNsense NAT: MVC SNAT (50) before legacy manual (100) before automatic (200) before one-way 1:1 (500); binat before nat; MVC SNAT applied in every mode up to 26.1.10, in hybrid and manual from 26.1.11; a port forward with *Register rule* adds `pass in quick` on its interface to the target (500000) | `_nat`, `_registered` |
| OPNsense restore of an area: a set of sections; those the file has replace the running ones, those it does not have are deleted; no section of the set, refused; no filter reload, no validation, migrations run but not for a `Filter` model whose version is not in the area | emitter, `OPNSENSE_RESTORE`, the judge's `restore` |
| SonicWall, all rows below: from SonicWall's knowledge base and documentation where it says so, otherwise from the published readers of the settings export (faridlav/SonicWallParser, pryorda/sonicwallRuleParser, angeloxx/dumpwall on GitHub). Nothing was run on a SonicWall | SonicWall parser and emitter |
| SonicWall `.exp`: Base64 of `key=value` joined by `&`, values URL-encoded, `&&` at the end (KB); the key names of address objects (`addrObj*`, type 1 host, 2 range, 4 network, 8 group), groups (`addro_atomToGrp`/`addro_grpToGrp`), services (`svcObj*`, `svcObjIpType` the protocol number), zones (`zoneObj*`), interfaces (`iface_*`, `interface_Zone`), access rules (`policy*`, `V6` for IPv6) and NAT (`natPolicy*`, interfaces by `iface_ifnum`, -1 any) (the readers agree) | SonicWall parser |
| SonicWall `.exp`: action 2 is allow, 0 and 1 are deny and discard in an order the readers disagree on; empty source, destination, service is any, empty translation is original; `Port1 0` with `Port2 N` is port N; the codes of `zoneObjZoneType` (0 untrusted, 1 trusted, 2 public, 4 wireless, 5 encrypted) are one reader's reading | SonicWall parser |
| SonicOS: access rules per pair of zones, first match by priority, the default ("Any") rule at the bottom of each pair; by default LAN/WLAN to WAN/DMZ and DMZ to WAN allowed, the reverse denied (documented); other security types not documented | parser (`_default_rules`), emitter (deny tails) |
| SonicOS: an access rule names the original (public) destination and the zone of the server; NAT policies one table, first match by priority, matching inbound and outbound interface; a reflexive policy adds its mirror (the shape of the mirror assumed) | SonicWall parser and emitter |
| SonicOS CLI: `configure terminal` (7; `configure` on 6.5), `commit`; `address-object ipv4 "N" host|network|range ... zone Z`, `address-group ipv4 "G"` with member lines, `service-object "N" TCP a b`, `service-group`, `access-rule ipv4 from Z to Z action allow source address any|name|group ... service ... destination address ...` with `name` and `no enable`, `nat-policy inbound ... translated-service ...` (KB). Assumed: `priority manual N`, `access-rule ipv6`, `address-object ipv6` and `fqdn`, the `name` and `comment` of a NAT policy, zone names with a space in double quotes | SonicWall emitter, `SONICWALL_LOAD` |
| WatchGuard, all rows below: from WatchGuard's Help Center where it says so, otherwise from the published readers of the configuration file (ins1gn1a/WatchGuard-Config-Parser, watchguard-toolbox-project/xmlcheck, MattParkin14/Watchguard-Firewall-Mapping on GitHub; read, never run). Nothing was opened in Policy Manager or loaded on a Firebox | WatchGuard parser and emitter |
| Policy Manager file: root `<profile>`; `address-group-list` (member type 1 host, 2 network with mask, 3 range, 8 domain), `service-list` (member protocol number, type 1 one port, 2 range, ICMP type and code with 255 any, protocol 0 any), `alias-list` (member type 1 address at an interface with a user, type 2 another alias), `abs-policy-list` (the policies in order, `firewall`, `enabled`, `from-alias-list`, `to-alias-list`, `service`), `policy-list` (the rule of each, `-00`), `interface-list` (`if-property`/`vif-property` 1 trusted, 2 external, 3 optional, 8 custom: one reader's reading), `nat-list` (static NAT `.snat`, type 7) (the readers agree where not said) | WatchGuard parser and emitter |
| Fireware: policies are first match in manual order; automatic order sorts them by how specific they are (Help Center), and the flag `auto-order-enabled` is found in two places by two readers (searched anywhere); the Firebox denies what no policy allows (Help Center); static NAT is an action in the To list of a policy, which names the public address (Help Center) | WatchGuard parser and emitter |
| Assumed when writing: `Allow` and `Deny` as the text of `firewall` in `abs-policy-list` (the readers show numbers and words), the members of a static NAT action as they are written, and that Policy Manager reads a file of policies whose aliases name interfaces by name | WatchGuard emitter, `WATCHGUARD_LOAD` |
| Barracuda, all rows below: from Barracuda Campus (the REST API pages and the how-to articles whose examples use it) where it says so; the rest assumed, and the keys of a rule also as an MCP server for the API on GitHub (LanceHardwoodXXX/Barracuda-MCP-v2; read, never run) sends them. Nothing was run against a CloudGen Firewall | Barracuda parser and emitter |
| CloudGen REST API: base `/rest/config/v1`, header `X-API-Token`; `GET forwarding-firewall/rules` (with `expand=true`) answers `{"rules": [...]}`; `POST forwarding-firewall/objects/networks` with `name` and `included: [{"entry": {"ip": ...}}]`; `POST .../networks/<name>/included` with `{"entry": {"ip", "interface", "comment"}}`; `POST forwarding-firewall/rules` (or `rules/lists/<list>`) with `name`, `source`/`destination`/`service` as `{"references": ...}`, `action: {"type": "block"}`, `position: {"placement": "top"}`; `PATCH forwarding-firewall/rules/<name>` with `{"deactivated": false}` (Campus examples) | Barracuda parser and emitter |
| Assumed: `ipVersion` `IPv4`/`IPv6`, `bidirectional`, `comment`, the action types `pass` and `deny`, `excluded` entries, service objects as `entries` of `{"entry": {"protocol", "ports", "clientPortUsed": {"from", "to"}}}`, a reference among the entries of an object, names of up to 32 letters, digits, `.`, `_` and `-` told apart without regard to case | Barracuda parser and emitter, `BARRACUDA_LOAD` |
| CloudGen semantics: first match, IPv4 and IPv6 rules apart, Block drops, Deny answers, what no rule matches is blocked, the interface of an entry counts in a source only, a bi-directional rule matches the other way round, excluded entries leave addresses out, an ICMP service entry matches every type (Campus) | Barracuda parser, emitter and judge |
| Forcepoint, all rows below: from the SMC API guide (7.x), Forcepoint's documentation of NGFW 6.x and 7.x where it says so, and the clients Forcepoint publishes for the API (smc-python, the Terraform provider, the Ansible collection; read, never run); the rest assumed. Nothing was run against an SMC | Forcepoint parser, emitter, loader and dump program |
| SMC API: versions from `GET /api`; `POST /{v}/login` with `authenticationkey` (a cookie session), `PUT /{v}/logout`; entry points from `GET /{v}/api`; `GET entry?filter=NAME&exact_match=true`; a `POST` answers with the href in `Location`; a list answers `{"result": [{"href", "name", "type"}]}` in policy order; a rule `POST`ed to the list of a policy goes to the top, at the insert point, and one `POST`ed to the `add_after` link of a rule after it (smc-python, API guide) | loader, dump program, the made-up SMC |
| Policy: based on a template up to a predefined one; at each insert point the rules the level below added there (`parent_insert_point`); first match; Allow, Discard, Refuse decide; Continue sets defaults (logging) for the rules below that match the same traffic; a jump goes into the sub-policy, and on with the next rule when nothing there matches; a NONE cell makes the engine ignore the rule; what no rule decides is discarded; the predefined Firewall Template ends in Refuse Ident and Discard all, logged (documentation) | parser, emitter, judge |
| Cells: members ORed; a match expression is one row whose parts are ANDed (smc-python, documentation); a zone in the source cell is the interface traffic arrives on, in the destination cell the one it leaves by (assumed); *broadcast* off leaves out the network and broadcast address in a rule cell (smc-python's description; FWShift also applies it to NAT cells, assumed); an exclusion of one element is the complement (documentation), of several not documented and not read | parser, emitter, judge |
| NAT: after the access rules, which match the addresses before NAT; first match; one rule translates source and destination; a port range translates to a range of the same size; element-based and default NAT after the NAT rules (documentation); a missing original port is every port (assumed) | parser, emitter, judge |
| Assumed when writing: a TCP or UDP service of ports 1 to 65535 for every port; an expression and a group may stand in a match expression; `used_on: {"any": true}`; Refuse answers TCP with an ICMP error, not a reset | emitter, `SMC_LOADER` |
| Juniper, all rows below: from Juniper's documentation (security policies, global policies, address books, predefined applications, application sets, NAT, static NAT, configuration groups, viewing the configuration) where it says so, and from the Junos grammar of Batfish (read, never run) for the exact statements; the rest assumed. Nothing was loaded on an SRX | Juniper parser and emitter |
| Junos: policies per pair of zones, first match, then global policies, first match, then the default policy (deny-all); static NAT, then destination NAT, then the policy (which sees the translated destination and its zone), then source NAT; NAT rule sets of an interface before those of a zone, first match within a set; an address name is looked up in the book of the zone, then the global one; global policies and NAT use the global book (documentation) | Juniper parser, emitter and judge |
| Junos syntax: `set security policies from-zone A to-zone B policy P match source-address/destination-address/application ...`, `match source-address-excluded`, `then permit/deny/reject`, `then log session-init/session-close`; `set security address-book global address N prefix / range-address A to B / dns-name H [ipv4-only/ipv6-only]`, `address-set`; `set applications application A [term T] protocol P destination-port N-M source-port ...`, `icmp-type`/`icmp6-type`; NAT `pool ... address A [to B] [port N]`, `rule-set ... from/to zone ...`, `match destination-port N to M`, `then destination-nat pool`, `then source-nat interface/pool/off`, `then static-nat prefix` (Batfish, documentation) | Juniper parser and emitter |
| Assumed: names of up to 63 characters (third-party documentation); `match from-zone`/`to-zone` in global policies (a published generator writes them); the definitions of the predefined applications of the table (documentation and Batfish agree; `junos-ping` they do not, and it is not used); that `display inheritance \| display set` shows what groups give where it applies; the order of NAT rule sets of one context | Juniper parser and emitter, `JUNOS_LOAD` |
| Terraform, all rows below: from Terraform's documentation of its JSON output and its source (`jsonstate`, `jsonplan`), and the documentation and schemas of hashicorp/aws (6.x) and hashicorp/azurerm; nothing was run with Terraform | Terraform parser and emitter |
| `terraform show -json`: format version 1; resources with `address`, `mode`, `type`, `name`, `index`, `values`, `deposed_key`; child modules; a plan's `planned_values` without unknown values (unknown list elements null), `resource_changes` with `actions`, `before` and `after_unknown`, `configuration` with `references` and `constant_value`, nested blocks as lists; `errored` and `complete` | Terraform parser |
| A refresh fills the inline `ingress`/`egress` of an `aws_security_group`, the `security_rule` of an `azurerm_network_security_group` and the `subnet_ids` of an `aws_network_acl` from the cloud, so that they repeat the separate resources; Terraform takes away the outbound rule AWS gives a new group (and the rules of a default group) unless declared | Terraform parser |
| The protocols of a rule as the providers keep them (names or numbers, `-1`, `all` for `aws_security_group_rule`); ports `0`/`0` or null for every protocol; ICMP type and code in `from_port` and `to_port`; Azure fields `""` and `[]` where not used, protocol names `Tcp`, `Udp`, `Icmp`, `Esp`, `Ah`, `*` | Terraform parser and emitter |
| Google Cloud, all rows below: from Google's Compute Engine API reference (`Firewall`, `FirewallPolicy`, `FirewallPolicyRule`, `Network`, `Instance`), the documentation of VPC firewall rules, network and hierarchical firewall policies and the gcloud reference; nothing was run against a project | Google Cloud parser and emitter |
| Order: hierarchical policies, regional system policies, then with `AFTER_CLASSIC_FIREWALL` (the default) the VPC firewall rules, the global network policy, the regional network policy, and the implied rules (ingress to an instance denied, egress allowed); `BEFORE_CLASSIC_FIREWALL` puts the two network policies before the VPC rules. A step that matches nothing goes to the next | Google Cloud parser and emitter |
| VPC firewall rules: lowest priority number first, a deny before an allow of the same priority; an ingress rule without a source is `0.0.0.0/0` (taken as every address of the rule's IP version); target and source tags match primary internal addresses; source ranges and tags are ORed; one IP version per rule; protocol `all`, numbers, ICMPv6 as `58`; no ICMP types, no source ports | Google Cloud parser and emitter |
| Network firewall policies: priorities unique per policy, user rules 0 to 2147483547, Google's `goto_next` rules after; one global policy per network; a rule needs a source (ingress) or destination (egress); `goto_next`; target service accounts, secure tags (ineffective ones ignore the rule); the match kinds that need Google's data (FQDN, geography, threat intelligence, address groups, network context) | Google Cloud parser and emitter |
| `get-effective-firewalls`: `firewalls` and `firewallPolicys` with `type` (`HIERARCHY`, `NETWORK`, `NETWORK_REGIONAL`, `SYSTEM_*`) and `rules`; hashicorp/google 5 and later for `google_compute_network_firewall_policy_rule` (major version 8 when written) | Google Cloud parser, Terraform emitter |
| `aws_vpc_security_group_ingress_rule` and `_egress_rule` take ports for TCP, UDP, ICMP and ICMPv6 only; a group of the same name in the VPC fails the apply; azurerm refuses to create a resource that exists and is not in the state; azurerm 4 needs a subscription id | Terraform emitter |

## Development log

### 2026-10-10: version 0.1.0

**Built**

* Neutral model, findings and report (text and JSON).
* PAN-OS parser: firewall and Panorama XML, vsys, `shared`, device-group
  hierarchy with pre- and post-rulebases, application groups, default-rule
  overrides.
* FortiOS parser: generic configuration tree (quoting, multi-line values,
  VDOMs), addresses and groups for both IP versions, services, virtual IPs,
  IP pools, per-policy NAT and central NAT.
* Emitters for both platforms, including NAT in both directions, rule types,
  name sanitising, placeholders.
* Command line with `convert` and `inspect`; zone, interface and application
  maps; target scopes; pruning.
* Two synthetic sample configurations with golden conversions.
* Renamed from the working name `fwconv` to FWShift.
* README, user manual, this file; GPL-3.0-or-later with SPDX headers.

**Reviewed**

An independent reviewer attacked the tool three times, with reproduction
scripts, a mutation fuzzer and a generator of structured configurations.

| Round | Found | Examples |
|---|---|---|
| 1 | 12 silent widenings, 3 crash classes, 6 wrong outputs, 5 minor | negation applied to the wrong IP version; objects named `any` read as the wildcard; objects named `all` redefining FortiOS built-ins; unknown FortiOS attributes ignored; rules on the internal address matching translated traffic; per-policy NAT translating traffic the source did not; unbalanced quote swallowing a deny |
| 2 | 8 | groups holding an FQDN hidden from the NAT analysis; one-sided IPv6 address lists; `--zone-map` merge creating an intrazone allow |
| 3 | 3 | missing PAN-OS elements read as "any"; gaps in reserved names |

All are fixed, each with a test in `tests/test_semantics.py`. Apart from the
crash classes of round 1, the fuzzers ran without a traceback in every round.

**Not done, known**

* No validation on devices (see the table above).
* The service of a rule behind a port-translating NAT is reported, not fixed.
* FortiOS output offers central NAT only.
* PAN-OS `set`-format input is not read.
* Schedules, users and groups, security profiles are not converted.

### 2026-10-10: version 0.2.0

**Built**

* iptables and ip6tables, read and written. The parser flattens user chains
  into the rules that jump to them and merges the matches exactly; the emitter
  writes lists and negations as chains.
* Check Point, read and written. The parser flattens inline layers, reads
  automatic NAT from object settings and marks predefined objects and
  gateways; the emitter writes a `mgmt_cli` script with inline layers per zone
  pair.
* Shared: `transform.lower_applications` (one implementation of application
  to port lowering for the three port-based targets), `to_post_nat_lookup`,
  `note_nat_order`, `harden`, `Policy.lookup_after_dnat`,
  `NatRule.combines`, `builtin` on every object class, `Report.retract`.
* PAN-OS output: NAT rules of a source without zones need
  `--target-nat-zone`.
* Packet-level equivalence tests in both directions for both new formats, and
  for iptables against a real kernel: rulesets loaded with `iptables-restore`,
  and real packets forwarded through netfilter.

**Reviewed**

Four more rounds by the independent reviewer, on the new formats and on the
changes to shared code. From round 6 on the reviewer had the kernel to check
iptables against, and used it.

| Round | Found | Examples |
|---|---|---|
| 4 | 12 silent errors, 2 injections, 1 emitter crash, parser tracebacks and hangs | `-s` next to `--src-range` overwriting each other; a comment with `::` turning an IPv4 ruleset into IPv6; a Check Point wildcard object read as one host; a rule type with zone `any` not applied between unnamed zones; a zone name with a line break starting a shell command in the script |
| 5 | 4 silent NAT errors, 2 understated findings, robustness gaps | first-match NAT order lost on FortiOS and iptables; the source half of a destination-and-source NAT rule matched on pre-NAT port and interface; an automatic NAT rule turned into an identity translation; `str.isdigit` accepting digits `int` cannot read; a translated port written unchecked |
| 6 | 5 silent errors (2 found by sending packets through the kernel), 2 understated, 3 robustness | NAT order shapes the first check missed; `-s a/0.0.255.255` read as a /16 because `ipaddress` accepts host masks; two `--icmp-type` matches where the last one won; a missing page of a Check Point export going unnoticed; `"enabled": "false"` read as enabled |
| 7 | 2 missed and 2 needless NAT order findings, nothing else | a hide rule bound to another zone than the original address; a no-NAT rule that shields the traffic anyway |

All are fixed, with tests at the end of `tests/test_iptables.py` and
`tests/test_checkpoint.py`. Round 5 also checked, with the reviewer's own
generators (some 1650 random models), that the Check Point emitter does not
widen for zones the policy names; merging zones with `--zone-map` does widen,
there as on the other targets, and is the user's choice. A generated script
with hostile names was run under sh, bash and dash against a stand-in for
`mgmt_cli`: every name arrived as one argument and nothing else was executed.

**Not done, known**

* No validation on PAN-OS or FortiOS devices or a Check Point management
  server. For Check Point the input format itself is unverified: the sample is
  written from the API documentation. iptables is verified for the filter
  table on one kernel and iptables version; its NAT output is not.
* NAT order between a first-match rulebase and per-direction tables is
  reported, not reproduced, and the check behind the report is a comparison of
  rule pairs by zone, address and service: every review round found a shape
  it missed. Treat `NAT_ORDER` as a list of places to look, not as proof that
  the rest is unchanged.
* An iptables `ACCEPT` in `PREROUTING` is not converted, not even to iptables:
  the model cannot say "exempt from destination NAT only".
* iptables: `INPUT`/`OUTPUT`, IPv6 NAT, `nft` syntax and most match modules.
* Check Point: several ordered layers per run, implied rules, identity,
  application control, VPN.
* Names that differ only in case are reported for Check Point, not resolved.

### 2026-10-11: version 0.3.0

**Built**

* Cisco ASA, read and written; the device configuration of an FTD, read.
  The parser takes the access lists that `access-group` binds, gives permit
  entries the interfaces their traffic can leave by (what an ASA never
  forwards; routes where the entry names addresses), adds the implicit rule
  of an interface without list, converts outbound lists that only deny, and
  reads twice NAT and object NAT in the order of the ASA. The emitter writes
  one access list per zone and a global one, object groups for lists,
  complements for negated addresses, and twice NAT.
* `--zone-network`: the networks behind a zone, with which a rule for one
  destination zone can be written for an ASA (how they are read was settled
  in round 9, below).
* Shared: `Rule.egress_implied`; `note_nat_order(whole=...)` for a target
  that translates per direction but can write a rule that claims a connection
  whole; `rewrite_destinations` maps part of a translated network to the same
  part of the other side and reports where it cannot
  (`NAT_DESTINATION_WIDENED`), and reports a rule that names the port on the
  wrong side of a port translation; `harden` refuses groups that hold
  themselves; the group resolvers are linear in the number of groups;
  `netutil.subtract`, `intersect`, `interval_text`; `Report.withdraw`.

**Reviewed**

| Round | Found | Examples |
|---|---|---|
| 8 | 4 silent errors (2 in shared code that predate ASA), 2 wrong facts, 2 crashes, an exponential blow-up, several refused or misleading outputs | a rule for one host behind a static NAT of a network became a rule for the whole network, on every same-kind conversion; a rule for the original port of a port translation, dead on the source, came alive on PAN-OS; an FTD configuration lost every permit because FTD has no `same-security-traffic`; `--zone-network` with overlapping or incomplete networks wrote wrong destinations as "exact"; a destination NAT written as a static rule translated the server's outgoing connections too; a group that holds itself crashed the ASA emitter; two groups per level that hold both groups below took minutes at 28 levels; the address of an interface written as an object, which an ASA refuses |
| 9 | 3 silent errors (2 in shared code, 1 brought in by the round 8 fix for `--zone-network`), 1 crash, 1 wrong fact, 9 statements in the documents that did not match the code | a rule naming addresses on both sides of one translation (a group with a real host and the mapped address of another) was widened without a finding; with networks for every zone and no default route, a deny rule was cut down to the networks given and the Internet fell through to the permit below; a port translation was not looked at on rules to any destination; `<translated-address>any` from PAN-OS ended in an `AssertionError`; new twice NAT lines go to the end of section 1, not in front |
| 10 | 4 silent errors (1 brought in by the round 9 service filter, 1 a gap of the strict `--zone-network` reading), 3 false needs-review findings | what a rule exposes depended on the order of the NAT rules (a rule for one of two public addresses of one server, flagged only when its NAT rule came second); a dead rule of iptables or FortiOS (public address, internal port) came alive on a target of the same kind; a negated destination naming part of a translated network kept its list and changed meaning; `inside=10.0.0.0/8` with no networks for a dmz inside it cut a deny for every other zone |

The findings of round 8 are fixed, with tests at the end of
`tests/test_asa.py`. The first of them was found by an oracle the tests
lacked: a same-kind round trip with NAT, access lists compared packet by
packet on real addresses. `random_lab` has NAT now. The reviewer checked the
facts it could against Cisco's documents (what it verified is marked in the
table of assumptions) and ran the parser against the tests' random ASA for
another 1200 seeds without a difference.

Round 9 looked at those fixes. What it found, and what was done:

* **Both sides of one translation.** `rewrite_destinations` now works out,
  per translation and rule, what the rule names on the new side that does not
  go with what it names on the side being left, and reports that part
  (`NAT_ADDRESS_EXPOSED`) whatever else the rule names. An addition is only
  silent when it puts back what the parser of a same-kind source took. The
  check also looks at the services: a rule for port 22 is not exposed by a
  forwarding of port 443 (that was a false finding in the Check Point golden
  report). Findings carry the NAT rule they are about (`Finding.subject`), so
  that a same-kind target withdraws only those of NAT rules it really gets.
* **`--zone-network`.** One way of reading the networks instead of two
  ("only" and "without"), and no assumption left in it: the networks of the
  zones a rule is not for are left out of its destination, and that is done
  only when every zone the rule is for or has to be told apart from was given
  networks. A zone without networks is not "the rest" (the first version of
  this fix said it was, and a forgotten zone inside the range of another one
  then made rules wider without a word). An address in none of the networks
  belongs to nobody: a permit for any address leaves it out, a deny keeps it
  (`ZONE_NETWORK_GAP`), and that goes for all of IPv6 when only IPv4 networks
  were given. "Everything else" for one zone while another has none is
  reported (`ZONE_NETWORK_INCOMPLETE`). A rule to every other zone is not
  touched, except for the zone's own networks. A rule left without an address
  is skipped with `EGRESS_NO_ADDRESS`, at needs-review for a deny. The
  reviewer's fuzzer for this (random models, nine ways of giving the
  networks, 300 seeds each) now finds every difference on a flagged rule, and
  none with complete networks.
* **Ports on rules to any destination** are checked, in both directions; the
  port form has its own code (`NAT_PORT_EXPOSED`), which a same-kind target
  withdraws. Protocols without ports (an ICMP rule) no longer count as a
  possible match.
* The crash, the `ASA_LOAD` text and the manual (section 10, step 4), the
  statements in the manual that did not match, the message for protocol and
  ICMP-type groups nested too deep, the object left behind for an interface
  address: fixed. iptables `DNAT` to a range is marked as picking an address
  per connection (`DestNat.spread`), so a rule for one of them is not mapped
  address for address.

Left as they are, on purpose:

* Before 9.0, an interface with only an IPv4 list gets no implicit rule for
  IPv6. Narrower, never wider.
* The assumption about NAT rules and routes in the table above.

Round 10 looked at the fixes of round 9, and led to the last change of this
version in `rewrite_destinations`:

* **Order.** Rules are the outer loop now. Hits are looked for in what the
  rule named before any translation, and what the rule exposes is worked out
  at the end, per translation, from what the rule names then. A translation
  that keeps the address and changes the port takes part in that (a rule that
  reaches the server through another NAT rule).
* **Services.** A NAT rule with a service does not rewrite a rule whose
  services cannot meet it, and does not count as exposed by it either: one
  filter for both, where round 9 had it for one. A public address with two
  port forwardings to two servers gives each rule the server of its port.
* **Same kind.** The parser notes what it adds (`Rule.nat_added`), and a
  target of the same kind takes away exactly that and nothing else. Round
  trips of iptables, FortiOS and ASA through the model are exact for the
  destinations, dead entries included; `NAT_ADDRESS_EXPOSED` and
  `NAT_DESTINATION_WIDENED` are withdrawn there with the other findings of a
  NAT rule that is written. FortiOS policies that name a virtual IP are the
  exception that is still rewritten (`Policy.named_translations`).
* **Negation** over part of a translated network disables the rule unless it
  names the same part of both sides.
* **Ports.** A service that holds both ports of a port translation is not
  reported.
* **`--zone-network`.** A rule to every other zone has its own zone's
  networks left out only when every zone has networks.

The tests for round 9 are at the end of `tests/test_asa.py` too, among them
`test_incomplete_zone_networks_never_widen_without_a_word`: random policies
converted with networks as a person might give them (a zone forgotten, IPv6
forgotten, one network missing, a default with a zone missing), where a packet
the model denies may only be allowed by an entry of a rule the report flags.

**Not done, known**

* Nothing was loaded on an ASA or an FTD. The ASA syntax written and the FTD
  syntax read are from documentation and memory; the table of assumptions
  lists what the emitter writes that nobody has seen an ASA accept.
* To an ASA, rules "to zone B, any address" are inactive without
  `--zone-network`, and the networks given are taken to be right. A zone or
  an address nobody mentioned is handled on the side that allows less; a
  network given to the wrong zone is not noticed.
* The fixes of round 10 were not reviewed again by the independent reviewer.
  They are covered by the tests named above and by the reviewer's own
  oracles, rerun after the fixes: no difference without a needs-review
  finding on a deciding rule in 2500 seeds each way between pre-NAT and
  post-NAT platforms, and no difference at all in the round trips of
  iptables, FortiOS and ASA.
* An FQDN destination on a rule from the zone a NAT rule serves gets no NAT
  finding: whether the name resolves to the published address cannot be
  known when converting.
* Destination zones from routes: static routes and connected networks only.
* ASA to ASA changes list names, loses `log` on denies and time ranges, and
  writes object NAT back as twice NAT.
* Outbound access lists beyond "deny, then permit everything", time ranges,
  identity matches, NAT before 8.3, IPv6 lists before 9.0, bridge groups,
  VPN filters, inspection.
* The older walkers over nested groups in the PAN-OS and FortiOS parsers and
  the iptables emitter were made linear in passing; they have no test of
  their own beyond the ASA one that goes through every emitter.

### 2026-10-11: version 0.4.0

**Built**

* `audit.py` and the command `fwshift audit`; `--audit` and its options on
  `convert`. Twenty-three checks in four groups: rules that allow a lot, the
  order of the rules, loose ends, and one that only exists after a conversion.
* Per check an action (`off`, `accept`, `report`, `disable`, and `reorder`
  for shadowed rules), per-rule acceptance with a reason, a JSON
  configuration file, `--audit-fail-on` with exit status 3.
* In a conversion the audit runs twice: on the policy as read, where the
  actions are carried out, and on the policy without the rules the
  conversion wrote disabled or left out. `EXPOSED_BY_CONVERSION` names the
  allow rules below a blocking rule that was lost.

**How a rule is proven dead**

A rule is a box: source zones, destination zones, whether the two are the
same zone or different ones, sources, destinations and services. Zones are
bits of an integer, with one bit for "the zones nobody names", so that `any`
is more than the zones of the policy; the relation is a dimension of its own,
which keeps a set of zone pairs at two integers instead of their product (the
first version had a bit per pair, and 2000 interfaces made integers of four
million bits). Addresses are the intervals of `netutil`, one IP version per
box: no packet goes from an IPv4 address to an IPv6 one. Services are
rectangles per protocol number (source port by destination port, ICMP type
by code) plus "every other protocol". A rule is dead when its box, with the
boxes of all earlier rules taken out, is empty.

Every rule has two boxes. *Over*: all it might match. *Under*: what it surely
matches. They differ where the model cannot say (a host name, a dynamic
group, a group with excluded members, `application-default`, an unsupported
object, an object or rule the parser reported as approximated). The rule that
is covered enters with its over box, the rules that cover with their under
box, so a wrong claim needs a wrong box, not an unknown. Applications, users,
URL categories and schedules are not in the boxes: an earlier rule that is
narrower in one of them than the later rule is left out as a cover. Two lists
with the same names are equal whatever the names stand for, which is what
makes rules with host names or `application-default` comparable at all.

What a parser said about its own reading counts (`Reading`, taken from the
report before anything else is written to it): a rule with a finding of
severity approximated or higher, other than those about destination NAT, is
neither called dead nor used as a cover; an object with such a finding
proves nothing by its addresses. A source that looks rules up after
destination NAT is read without the pre-NAT addresses its parser added
(`Rule.nat_added`): those stand for the translated traffic, not for
everything sent to that address.

The decision is made in three steps, because the obvious one (take the
earlier rules out in their order) cuts a broad rule under three thousand host
rules into three thousand pieces before it reaches the clean-up rule that
holds all of it:

1. *Counting.* If the earlier rules together hold fewer addresses and
   services of the rule than the rule has, something is left, however they
   lie. That settles nearly every rule that is alive without cutting anything.
2. *Largest first.* Otherwise the covers are taken out starting with the
   largest; then in their order, should that fall into more than 4096 pieces;
   then the rule is listed as not followed.
3. *Who takes part* is only asked for a dead rule (and for
   `OVERLAPPING_RULES`), and answered in the order of the rules, as first
   match would: a rule takes part when the rules above it leave it something
   of this rule. In few pieces that is read off while taking the covers out
   in order; otherwise cover by cover.

Most pairs of rules never get that far: a rule is first tried against the
others on the lowest and highest address of each side and on its zone bits,
in one list comprehension.

A dead rule is `REDUNDANT_RULE` when earlier rules with the same kind of
action that are themselves alive hold all of it, and `SHADOWED_RULE`
otherwise. A rule that is alive is redundant when a later live rule with the
same action, logging, profiles and handling holds all of it and every rule
in between that touches it handles traffic the same way.

**Why disabling them is safe, all at once**

A dead rule is missed by no packet. A rule that "adds nothing" hands each of
its packets to the next rule that matches it; every such rule up to the one
that holds it all handles traffic alike, or the finding would not have been
raised; and the rule that holds it all is alive and therefore not itself
removed as dead. If it is removed as adding nothing, the same argument goes on
from there, and the chain ends because it only goes down. Actions that do
change verdicts (disabling for what a rule allows, reordering) are carried
out first, and the order is looked at again before anything is disabled as
dead.

That argument is about one policy, and a conversion has two: what the source
enforced and what the target will. They differ in more than the rules that
are lost. A target that matches on the other side of destination NAT has
other addresses in the same rule; `--zone-map` can make two zones one. So a
rule is disabled only when it changes nothing in both: in the policy as read
without the rules the target cannot take, and in the copy the emitter writes
from (`Options.written`, from a conversion on trial), read as it stands. The
same is checked once more after the real conversion (`EXPOSED_BY_CONVERSION`,
"is needed again").

**Tests**

`test_audit.py` has an oracle that shares nothing with the audit's sets: a
small world (three named zones and two that no rule names, the addresses and
ports at which any two rules of the policy can differ) in which every packet
is walked through the rules, first match, with the matching code of the
iptables tests. For random policies where everything can be read, the rules
the audit calls dead are exactly the rules that decide no packet, and the two
findings are told apart as the walk tells them apart. Disabling what the
audit flags leaves the verdict, logging and action of every packet as it was.
For policies with host names, applications on default ports, schedules and
unsupported criteria the same is checked under several ways of filling in
what the model leaves open. Reordering changes only packets that a moved rule
now decides. The two ways of finding the rules that take part are run against
each other, the count of services against "a set is as large as its two
parts", and iptables rulesets with NAT are disabled-and-compared packet by
packet.

**Reviewed**

Two rounds by the independent reviewer, who wrote oracles of its own (a world
of 1.4 million packets with every packet one bit of an integer; a plain
subtraction in rule order without cap or filter; real parsers and emitters
with the outputs compared packet by packet with and without `disable`).

*Round 11*, on the first version: 11 findings, all fixed.

| | Finding | Fix |
|---|---|---|
| high | iptables, FortiOS, ASA: the pre-NAT addresses a parser added were read as matched, so a rule for the published address was "redundant" next to the rule for the server | the audit reads such a source without `nat_added`; a FortiOS virtual IP in a policy proves nothing about the plain address |
| high | a group with excluded members (FortiOS), or any unsupported or dynamic group, counted with its listed members as a cover | such a group proves nothing |
| high | rules the parser itself had reported as approximated (installed on one gateway, unknown attributes, per-policy NAT) were compared as if exact | `Reading`: left out on both sides and listed; `Rule.handling` |
| high | a rule was disabled as redundant next to a rule the target then could not write | conversion on trial before anything is disabled; the net after the conversion |
| medium | `NO_LOG=disable` disabled blocking rules | `NO_LOG` and `NO_PROFILE` cannot be `disable`; `NO_LOG` only where the model holds logging |
| medium | a bit per zone pair: 2000 interfaces took minutes and gigabytes; broad rules under thousands of host rules were "not followed" | zones as three dimensions; counting, largest first |
| medium | `ANY_ANY_ANY` was never high on an ASA or iptables source, where every rule names its interface | one level lower only when a rule does not reach every other zone |
| medium | `EXPOSED_BY_CONVERSION` missed the default for traffic inside a zone; the summary counted only the first audit | both |
| low | a rule from IPv4 addresses to "any" was compared in IPv6 as well | a box per IP version |
| low | a configuration with an unknown check and only a level ended in a traceback | refused with a message, as every unknown key now is |
| low | `[` in a rule name was a pattern; an acceptance nothing answered to went unnoticed; `--to json` ignored audit options | names first, two wildcards, *Accepted, but not found*, refused |

*Round 12*, on the fixes: the eleven confirmed fixed; the new decision code
compared with plain in-order subtraction on 310,000 rules of 2,960 policies
(identical check, dead set and related rules) and with first match on 9.6
million packets; six new findings, all fixed.

| | Finding | Fix |
|---|---|---|
| high | `disable` was proven on one side of destination NAT and written for the other: iptables to PAN-OS, a drop for the server's address and port was "redundant" and was the rule that blocked the published address there (5 of 2000 random rulesets wider, 9 narrower); PAN-OS to iptables the same in the other direction | the proof is given on the emitter's copy as well (`Options.written`) |
| medium | `--audit-accept 'no-*'` also accepted the `EXPOSED_BY_CONVERSION` of those rules, which was then not listed anywhere | accepted only by the name of the check; accepted findings of the second audit are listed; a rule that was accepted as dead and matches in the output is still named |
| low | `--audit-fail-on` counted the other findings of a rule the audit had disabled | they do not count |
| low | an acceptance pattern with many `*` did not return (a regular expression) | a matcher written out |
| low | policies in which nearly every rule is dead: 3000 rules in 84 s | rules that take part are read off in order while the rule stays in few pieces: 49 s. Still the slow case |
| nit | iptables wrote an audit-disabled rule as "disabled in the source"; an object read approximately was listed as a duplicate | both |

The fixes of round 12 were not reviewed again. They are covered by the tests
at the end of `test_audit.py` and by the reviewer's own scripts, rerun after
the fixes with the flow of the CLI as it is now: across the two sides of
destination NAT (iptables to a pre-NAT reading, 1500 rulesets; PAN-OS-kind
policies to iptables, 600) no packet differs with and without `disable`; nor
in same-kind conversions (iptables with NAT 400 + 250 seeds, without 250;
FortiOS 200 + 250; ASA 200 + 150), in the 1.4-million-packet world (500
static and 600 open policies; reordering and mixed actions 500 each) or
against the in-order reference (350 policies). In that world four dead rules
of the 500 static policies are not called dead; what is left of each lies
between the addresses the world has (the reviewer traced such cases to the
same conclusion), and with four more addresses in the world the audit and
the world agree on every rule of those policies.

**Not done, known**

* The audit has seen synthetic policies only.
* It is quadratic in the number of rules: 3000 rules take about five
  seconds, 6000 about half a minute on the machine it was written on (random
  policies, a third of the rules dead). Where nearly every rule is dead it is
  ten times that.
* "Never matches" is a statement about the model. The audit leaves out what a
  parser *said* it read approximately; a parser that is wrong without saying
  so makes the audit wrong. `audit.run` called without the parser's report
  knows nothing of either.
* The proof on what is written uses the emitter's copy of the policy, not
  the output text. What an emitter decides while writing (the networks an ASA
  rule is kept to with `--zone-network`, the chains of iptables) is not in it.
* The second audit lists new findings on the policy as read without the lost
  rules, not on the emitter's copy: a rule that is dead only as the target
  matches (after a destination was rewritten) is reported by the NAT findings
  of the conversion, not by the audit.
* The reviewer's fuzz across the two sides of destination NAT is not in the
  repository; `test_audit.py` has the two hand-made cases.
* No zone ranks, no hit counts, no audit of NAT beyond shadowing, no
  comparison of the output read back.
* `NO_LOG` and `NO_PROFILE` rest on what each parser reads of logging and
  profiles, which was written for the conversion report, not for an audit.
  `NO_LOG` is not raised for FortiOS: the model does not hold `logtraffic
  utm` apart from `disable`.
* A host name on a rule is compared by name only (two rules with the same
  name are equal, a name and an address never are).

### 2026-10-11: version 0.5.0

**Built**

* `matrix.py` and the command `fwshift matrix`: per ordered pair of zones the
  services the policy allows there and the rules that allow them, as text
  (a grid and a list of conduits), JSON or CSV.
* Zones of the policy, or zones given as networks (`--network-zone
  NAME[@ZONE]=NETWORK,...`), which is how the zones of a zone and conduit
  model are laid over a firewall that knows interfaces.
* `TODO.md`, with the to-do list that was at the end of this file and the
  firewall brands that are planned, one per release.

**How it is made**

The matrix is a second reader of the audit's sets. For every allow rule that
is enabled and not dead it takes the rule's *over* boxes and takes out the
*under* boxes of the blocking rules above it (largest first; a rule that
falls into more than 4096 pieces is shown as written). Earlier allow rules
are not taken out: what they take is allowed all the same, and the union per
cell is exact without it. What is left is a list of boxes, and each box is
laid into the cells it reaches:

* between the zones of the policy, a box reaches every pair of its source and
  destination zone bits that its relation (same zone, different zones)
  allows, with the bit for "the zones nobody names" as a row and column of
  its own;
* between zones given as networks, every pair of zones its source and
  destination addresses meet. A zone that is said to lie behind zones of the
  policy (`@ZONE`) takes a box only when the box is for one of those.

"At most what is allowed, never less" follows from the two boxes: allow rules
enter with all they might match, blocking rules with what they surely do.
The default (traffic no rule decides, where the policy lets it through) is a
pseudo-rule at the end: the universe of a cell minus the under boxes of every
rule without an application, user, category or schedule.

Decisions that were not obvious:

| Decision | Reason |
|---|---|
| Entries per rule are "what no *blocking* rule above takes", not "what the rule decides first" | The union per cell is the same, the subtraction is far smaller, and a reader who looks for "which rules let office reach the DMZ" wants every rule that would. Rules that never match are left out, so the list is not padded with dead rules. |
| A service that cannot be read is named (`svc:Facebook`), not shown as "any" | A Check Point rule for an application object is not a rule for every service; "any ~" on every such rule made the grid useless. Internally the entry still holds every service, for whoever asks the matrix what could get through. |
| A FortiOS virtual IP stays a name in the rule, and the box is cut to the mapped address when it is placed | Replacing the name by the address (the first version) broke the comparison by name with a blocking policy for the same virtual IP above it: "deny SSH to the VIP, allow the VIP" showed as any. |
| A zone of the policy nothing is given for, and an address that lies behind "the wrong" zone, go to a row `(ZONE: other addresses)`; the latter only for rules that name the address | The networks a user gives need not be all there is behind a zone, so a rule must not vanish for it. Showing it under the zones given for its own zone would be a guess (the first fix did that, and "deny telnet from the office, allow the rest of the zone" then showed telnet for the office). Doing it for rules with "any" address would add such a row to every matrix: "any" names no address behind another zone. |
| Destination NAT of a pre-NAT source is followed for every NAT rule that translates a destination, with "any zone" where the translated address cannot be read | `destination_translations` returns only the shapes the converter can rewrite (one published address). A matrix cannot leave the others out: the first version lost the rule. |
| What the parser said about the whole policy is printed with the matrix | "Nothing is allowed" next to a `policy6` table that was not read, or to VPN traffic that bypasses the access lists, is a wrong answer however exact the matrix is about what was read. |
| The intrazone default is not shown for network zones without `@ZONE` | Whether two networks lie in one zone of the firewall is what `@ZONE` says. Without it the default would be in every cell of every PAN-OS matrix. A note says that it is missing. |
| An iptables ruleset has a default for one IP version | The file is for IPv4 or IPv6; "any" for the other half made every cell "any" under a `FORWARD ACCEPT` policy. |

**Tests**

`test_matrix.py` walks the small world of the audit tests packet by packet
and notes, per pair of zones, which services each allow rule passes that no
blocking rule above it takes, which packets each rule decides, and which
services no rule decides. For policies that can be read exactly the matrix
equals that, entry by entry, with random defaults (150 seeds) and between
zones given as networks, unbound, bound and two behind one zone (90 seeds);
for policies with host names, applications, schedules and unsupported
criteria every packet that gets through under three ways of filling in the
unknowns is in its cell (40 seeds). Sixteen deliberate mistakes in
`matrix.py` (blocks not taken out, dead rules shown, relation ignored,
bindings ignored, NAT rules of one shape only and so on) are each caught by
the tests. The random oracle has no NAT: NAT placement, virtual IPs, the
rest-of-zone rows and the parser notes have hand-made cases.

**Reviewed**

*Round 13* by the independent reviewer, on the matrix and on the fixes of
round 12. Its own oracles (policy zones: 2500 static and 1500 open policies;
network zones: 2000 and 900; pre-NAT sources with destination NAT, 1500
seeds in four ways of declaring zones, 44,563 allowed packets; real parsers
against packet simulators for iptables, ASA and FortiOS, 500 seeds each)
found no allowed packet missing. Seven findings came from hand-built cases:

| | Finding | Fix |
|---|---|---|
| high | Between network zones with `@ZONE`, a rule for a published address vanished when its NAT rule named two addresses, translated to a host name, or was a static NAT of a range; more generally any rule whose zone and addresses contradicted the networks given vanished without a word | every NAT rule that translates a destination is followed; rows for the rest of a zone; a note should a rule still be in no cell |
| high | Notes of the parser about traffic outside the model (VPN bypass, implied rules, tables not converted) were not shown: "nothing is allowed" next to an unread `policy6` | printed with the matrix, and in the JSON |
| medium | An IPv4 iptables ruleset with `FORWARD ACCEPT` showed "any" in every cell: the IPv6 half of the default | the default of an iptables ruleset is for its IP version |
| medium | FortiOS: deny for a virtual IP, then allow for the same one, showed "any" without a mark | the name stays in the rule |
| low | A policy named `(default)` or an interface named `(other zones)` passed for the matrix's own entries | a flag instead of a name; another label when the name is taken |
| low | A thousand rules for any zone on fifty zones: 110 MB of text, 2.6 GB of memory | such rules are listed once in the text (280 kB); cells share entries (1 GB). JSON and CSV are as large as they were |
| nits | `(elsewhere) -> (elsewhere)` called "inside the zone"; a zone no rule names refused; duplicate networks; `a@=`; DEL and U+2028 in names; a raw line break in an error; `-o -` wrote a file named `-` | all fixed; U+0085, U+2028 and U+2029 are now control characters everywhere names are made safe |

The reviewer confirmed the six fixes of round 12, with a fuzz across the two
sides of destination NAT in seven directions (PAN-OS-kind to iptables,
FortiOS and Check Point, with zones merged and with objects renamed;
iptables to PAN-OS, iptables, FortiOS and Check Point): 2.7 million packets
compared with and without `disable`, 13,000 rules disabled, none decided
differently.

The fixes of round 13 were not reviewed again. They have tests at the end of
`test_matrix.py`, and the reviewer's oracles were rerun on them (policy
zones 800 static and 500 open policies, network zones 500 and 300, pre-NAT
with NAT 500 seeds in four modes, real parsers 100 to 200 seeds each, 600
mutated inputs through the command): no allowed packet missing, no
traceback.

**Not done, known**

* The matrix has seen synthetic policies only.
* The random oracle of the tests has no NAT. The reviewer's NAT oracle is
  not in the repository.
* Rows for the rest of a zone are checked by hand-made cases only.
* With network zones and no `@ZONE`, what the firewall allows by default
  inside a zone is not in the matrix (a note says so).
* Port translation, source NAT and routing are not applied. Applications are
  not turned into ports.
* JSON and CSV repeat a rule for any zone in every cell: a thousand such
  rules on fifty zones are 280 MB of JSON and a gigabyte of memory.
* A conversion with `--audit-action ...=disable` converts twice (once on
  trial) and takes about twice as long as `--audit` alone.

### 2026-10-11: version 0.6.0

**Built**

* Sophos Firewall (SFOS 18 and later), read and written: `parsers/sophos.py`
  and `emitters/sophos.py`. The input is the export of *Backup & firmware >
  Import export*, as the `.tar` it comes in or as the `Entities.xml` inside,
  or what the XML API answers to a `Get`. The output is an `Entities.xml`,
  or the archive itself when `-o` names a `.tar`.
* `xmlread.py`: XML from outside is refused when it declares a document
  type, whatever its encoding. The PAN-OS parser uses it too; its check was
  on the bytes of the file, which a UTF-16 file passes.
* The audit takes logging and profiles of a Sophos rule into account
  (`NO_LOG`, `NO_PROFILE`); the matrix reads a Sophos policy like any other.
* Compressed input (gzip, bzip2, xz, zip) is refused with a message that
  says so, for every format.

**What the format made necessary**

* *Exclusions.* A Sophos rule is skipped for traffic that matches all the
  kinds of exclusion it has. The model negates per field. Read: one model
  rule per kind of exclusion, each with that field cut down (zones by set
  difference, addresses out of "any" as a negation, addresses out of a list
  as the ranges that are left, services out of "any" as a negated service).
  Written: one negated field is an exclusion; of several, all but one are
  written as complement ranges, and where that cannot be done (a host name)
  the rule is disabled. A negated service always stays the exclusion.
* *IP versions.* Two rulebases. "Any" of an IPv4 rule is `0.0.0.0/0` in the
  model. Written, a rule that matches both versions is two rules, hosts and
  groups are of one version, and a group of the model becomes up to three
  (`name`, `name_v6`, `name_fqdn`): groups are flat on a Sophos Firewall.
* *NAT rules match interfaces.* Read, an interface becomes its zone where
  the export holds the interfaces. Written, the interfaces come from
  `--interface-map`; without it the rule is for any interface and says so.
* *Linked NAT rules* take their match from a firewall rule. They are read as
  rules of their own, with a finding where that is more than they were.
* *An import overwrites by name and can stop midway.* So: no zones are
  written, names of services a firewall comes with are avoided, names of
  another platform are kept apart whatever their case, every rule stands
  after the one before it, and a placeholder is something no firewall
  refuses and nothing matches (a host name under `.invalid`).

**Sources**

Sophos Firewall help (firewall rules, NAT rules, import and export), the XML
API reference (IP host, services, NAT rule, interface), the templates of
Sophos's Python SDK (`sophosfirewall-python`: firewall rule, IP host,
service, groups, zone), a community script that reads NAT rules from the
API, and a third-party knowledge base for how exclusions combine and which
side of a translation a rule sees. What comes from where, and what from
none of them, is in the table *Vendor behaviour the code relies on*.

**Review**

*Round 14* by the independent reviewer. Its own oracles, written without
the project's test reader: random `Entities.xml` against the parser (4,500
files, 36,000 rules, 1.8 million packets), random models of all six vendors
against the emitter (5,000 models, 1.5 million packets), Sophos to Sophos
(4,500 files), Sophos to iptables, ip6tables, FortiOS, Check Point and ASA
(800 files each), and the audit's `disable` and `reorder` with a Sophos
source or target (6,000 policies). No packet was decided differently
without a finding on the rule that decides. The findings came from NAT and
from hand-built cases:

| | Finding | Fix |
|---|---|---|
| high | A destination NAT rule was given the zone it arrives in as the zone of its original destination. For a rule that redirects ("DNS from the LAN to the resolver", destination any) that made a PAN-OS rule "from LAN to LAN", which redirects nothing that leaves; in the other direction a PAN-OS rule for traffic towards one zone became a Sophos rule for all of it, without a word | the zone is taken from the networks of the interfaces where they tell, and is "none" otherwise (PAN-OS then asks for `--target-nat-zone`); `NAT_DESTINATION_ZONE` when a rule loses that limit and names no address, or many |
| medium | A zone or interface called `Any` (from PAN-OS, iptables or an ASA, or through `--zone-map`) was written as `<Zone>Any</Zone>`: every zone | the conversion stops and asks for another name |
| medium | A NAT rule linked to a disabled or blocking firewall rule became an active rule of its own | converted disabled (`NAT_LINKED_INACTIVE`); a link to a name two rules have is not followed |
| medium | Port ranges that start at 0 were written as they were; a Sophos service starts at 1, and a refused entity can end an import | port 0 is left out (`PORT_ZERO`) |
| medium | Security Heartbeat on a rule was reported as an inspection profile; it says who the rule is for | a condition: the rule is unsupported, for every target |
| low | Read too kindly: a status that is neither Enable nor Disable, a list or action given twice, text next to list members, a position FWShift does not know, a `<UserPolicy>` next to a `<NetworkPolicy>`, entities in a namespace (ignored, also blocking rules), group membership given on the IP host, a network with mask 0.0.0.0, an IPv4 address in an IPv6 host, ICMPv6 elements in an ICMP service, `*` inside a host name | each makes its rule or object unsupported, or is read as what it says; namespaces are stripped |
| low | Severity: "any zone except" on a blocking rule (a zone the file does not hold is no longer blocked), an interface that was all that limited a NAT rule, load balancing methods and health checks, shaping and gateways of a rule | REVIEW for the first two; `NAT_LOAD_BALANCING`; `HANDLING_NOT_CONVERTED` |
| low | The emitter wrote "ICMP code N of every type", which nothing reads; `NAT_STATIC_RANGE` was missed for addresses without an object; a NAT rule translated to a network object | unsupported; fixed; what a rule translates to is written as an address or a range |
| low | API answers: "No. of records Zero." became a rule called "unnamed"; a failed login was an empty policy; a second `<Configuration>` was ignored | skipped; an error; an error |
| low | The check for a document type was on bytes: a UTF-16 file passed it and had its entities expanded | `xmlread.py`, also for PAN-OS |
| low | 20,000 rules in export style took 76 s, a rule with 200,000 members 267 s | 8 s and 10 s through the command: the search for a rule's place and a list without duplicates were quadratic |
| nits | Two `Entities.xml` in one archive; a `.tar.gz` gave an error about quotes; a zone called `local` taken for the firewall itself; ICMPv6 type 0; `SOPHOS_LOAD` only informational although imported rules land below existing ones; a placeholder sharing its host name with an object of the policy | all fixed |

The reviewer also went through `SophosConfig`, the reader the tests stand
on. It found it strict where it matters and named four gaps: it took `Any`
as a zone name and a network as what a rule translates to (both closed), no
generator produces port 0 (a test does now), and it ignores ICMP codes,
because the packets of the tests have none (open).

The fixes were not reviewed again. They have tests at the end of
`test_sophos.py`, and the reviewer's scripts were rerun on them: the parser
oracle (1,500 files, 600,000 packets), the emitter oracle (600 models), the
round trips (900 files), the five other targets (150 files each), the
audit (1,100 policies), its reproductions of the findings and its hostile
inputs (about fifty archives and XML files, no traceback). Every difference had a
finding, as before.

**Not done, known**

* Nothing has been imported on a Sophos Firewall. The reader of the tests
  and the code share one reading of the documentation.
* The element names of a NAT rule's match and the first line of the file
  are from memory of exports. If they are wrong, FWShift reads such a NAT
  rule as unsupported (not as a wider rule), and writes NAT rules a firewall
  will not take: the import would stop at the first of them.
* How exclusions combine is from a third-party source. If they did not
  apply together, rules with exclusions of several kinds would be read too
  wide: the split writes "skipped only where all hold".
* Whether a rule sees the original or the translated service of a port
  translation is not known.
* Users and schedules are not written, also Sophos to Sophos. Linked NAT
  rules come out as rules of their own, IP lists as host groups. A file
  FWShift wrote names interfaces without saying which zone they are in:
  read again, its NAT rules are for any zone, and say so.
* The NAT oracle of the tests knows first match and what a rule translates
  to. It does not send a packet through a translation and on to the firewall
  rules; that is what the reviewer's NAT oracle of round 12 did, for other
  platforms.
* SFOS before 18, Sophos UTM, web server protection, device access and VPN
  are not read.

### 2026-10-11: version 0.6.1

**Built**

* A release workflow (`.github/workflows/release.yml`). Every version tag
  gets a GitHub release with `fwshift-X.Y.Z.zip` (the project as tagged),
  `fwshift-X.Y.Z.pyz` (one file that runs with Python 3.9 or newer, nothing
  to install), the wheel and the source distribution.
* Run by hand with a tag, the workflow gives a version that was tagged
  earlier its packages.
* `pyproject.toml` gives the licence as an SPDX expression with the licence
  file, which is what setuptools asks for now (it builds from 77 on).
* The converter itself is as it was in 0.6.0.

**How it is made**

The workflow is shell steps and nothing else, so that it can build an old
tag, which holds no build script. The zip is `git archive` of the tag under
`fwshift-X.Y.Z/`. The single file is the package with a `__main__` of its
own: the one `zipapp -m` writes calls `main()` and drops what it returns, and
the exit status of FWShift means something (1 for an error, 2 for `--strict`,
3 for `--audit-fail-on`). The text of a release is what the log entry of the
version lists under **Built**.

**Verified, and not**

The steps were run outside GitHub, in a copy of the project with a commit and
a tag: the version check (also with a tag that does not match, and one that
is no version), the packages, their checks, and the release notes for every
version in this log. The same steps built and checked the packages of 0.1.0
and 0.3.0 from the trees of those versions, as a run by hand for an old tag
would. Not run: the workflow on GitHub itself, so neither the
trigger on a tag, nor the two actions it uses, nor the step that creates the
release with `gh`. A test (`test_cli.py`) keeps the version, this log, the
manual and the README in step, and the line of `__init__.py` in the form the
workflow reads.

### 2026-10-12: version 0.7.0

**Built**

* Cisco Secure Firewall, read and written, for both of its managers:
  `parsers/cisco.py` and `emitters/cisco.py`, as the formats `fmc`
  (Management Center) and `fdm` (Device Manager).
* Read from a Management Center: the JSON its REST API answers, saved to a
  file. Access rules in their sections, with the policies a policy inherits
  from; the prefilter policy (Fastpath, Block, Analyze, tunnel rules, its
  default for tunnels); objects, groups and what a rule spells out; manual
  and automatic NAT in the order the device applies it. `--policy` and
  `--nat-policy` choose among several.
* Read from a Device Manager: its configuration export, as the text file or
  as the zip it comes in, or what its REST API answers.
* Written for a Management Center: a Python script (`--to fmc`). It holds a
  loader, `emitters/fmc_loader.py`, and the policy as data. The loader lists
  what the Management Center has, stops before it creates anything when a
  name is taken, creates objects, a new access control policy and a new NAT
  policy, assigns them to no device, checks the rules it made, keeps a
  journal and can undo its run. `--show` and `--dry-run` look first.
  `--target-policy` names the policies.
* Written for a Device Manager: a file for its configuration import
  (`--to fdm`).
* The audit takes logging and inspection of a rule of both managers into
  account; the matrix reads their policies like any other.
* An ASA target writes "the interface" again for a NAT rule that was read
  from a Management Center or a Device Manager as the address of one.
* Groups nested more than 64 deep are not converted, for every source: the
  passes that follow groups into groups would not come back from them.
* Two samples, `fmc_sample.json` and `fdm_sample.txt`, with their
  conversions to every target, and the conversions of the other six samples
  to both managers.
* The release workflow checks that the single-file package finds the loader
  inside itself and writes a script that runs.

**What the platform made necessary**

* *Two lists in front of each other.* The prefilter policy is evaluated
  before the access rules. Fastpath and Block are final, so its rules are
  read as the first rules of the policy. Analyze is not: it hands traffic to
  the access rules and ends the prefilter for it, which one list cannot say.
  The Analyze rule itself is nothing to convert; a Fastpath rule below it
  that overlaps it is not converted (it would let through what the access
  rules were to decide), and a Block rule there is kept and reported.
* *Inheritance.* The mandatory rules of a parent come before those of its
  child, its default rules after them. Where a policy says that it inherits
  is the least certain part of the format (below): the reader takes three
  forms, and says so when it finds none.
* *Source ports and destination ports are two conditions.* Read: one
  service with both. Written: a rule per set of source ports, each with the
  destination ports that go with it.
* *No negation.* Written as the addresses that are left; a negated list
  with a host name, or a negated service, cannot be written, and such a rule
  is left out rather than written without its negation.
* *Objects say one thing.* A port object is one port or range of one
  protocol, a network group holds no host names, a port group no groups: a
  service of the model becomes a group of objects, a host name moves from
  the group into the rules that use the group.
* *The only way into a Management Center is its API,* and every reference
  needs the id an object got when it was created. So the output is a
  program. It was built to be read and to be stopped: nothing that exists is
  changed, nothing is assigned, everything created is written down.
* *A Device Manager has no disabled rules,* and an import replaces what has
  the same name. So: rules that are disabled or cannot be converted are left
  out and reported as skipped, no placeholders, no zones in the file.
* *NAT is the ASA's.* The reading of manual and automatic rules follows the
  ASA parser; a manual rule with a destination is the rule of its
  connections; access rules name real addresses and are rewritten for the
  model, and back for the NAT rules that are written.

**Sources**

Cisco's REST API documentation for both managers (quick start guides, the
import and export chapter of the Device Manager guide), the configuration
guides for access control, prefilter and NAT, and the tooling Cisco and its
community publish, which is where most field names come from: the Python
client `fmcapi`, the Terraform providers for the Management Center, and the
API specification that ships with Cisco's Ansible modules for the Device
Manager. None of it was checked against an answer of a real manager. What
comes from where is in the table *Vendor behaviour the code relies on*.

**Review**

*Round 15* by the independent reviewer, with its own generators and
evaluators (none of the project's test helpers as judges): random Management
Center JSON against the parser (600 policies, 6,365 rules, 240,000 packets),
random Device Manager exports (600, 240,000 packets), its own policies
through eight pairs of source and target with its own readers of the script
and the import file (720,000 packets), the same through the project's
simulators for the other platforms (323,000 packets), random models to both
managers (1,200 models, 360,000 packets), the eight samples to both, NAT
followed through to the access rules (500 policies, 30,000 packets), a
mutation fuzz of both readers (4,060 inputs), about 90 hostile files through
the command line, and about 85 scenarios of a hostile or sloppy server
against the loader, 45 of them over real HTTP and HTTPS. No packet got
through a converted policy that the device would not let through without a
finding on the rule that decides. The findings were in the loader, in what
the reader does with an incomplete input, and in the documents:

| | Finding | Fix |
|---|---|---|
| high | A child policy was read without its parent, silently, when nothing in the input said that it inherits; the recipe of the manual did not fetch what says so, and the error for several policies pointed the user at `--policy` | the inheritance settings are in the recipe; a parent is also told from rules in the list of a policy that name another; where nothing tells, `INHERITANCE_UNKNOWN` at review level |
| high | The loader followed redirects, and sent the password and the token along, also from https to plain http | no redirect is followed; it is an error that says why |
| medium | The journal was not true after a call that was carried out and answered badly (a 500, a page of HTML, half an answer): objects existed that `--undo` did not know | after such a call the loader asks what is there; an object is the run's if it was not there before and says what was sent |
| medium | The journal was first opened after the first object existed and rewritten in place: a path that cannot be written gave a traceback with a zone already created, a full disk a journal that could not be read | written before anything is created, replaced in one step, per call; `--name` is checked like `--target-policy` |
| medium | From a Management Center to a Management Center, names FWShift made up held colons (`h-2001:db8::1`) and could differ from a name of the source in case only | made-up names follow the strict rule whatever the source, and names are kept apart whatever their case |
| medium | A policy without the list of its rules, an error of the API saved in place of an answer, a list that says it has rules and holds none, and items of a rules list with a type FWShift does not know were all passed over without a word | `EXPORT_INCOMPLETE` for each |
| medium | `--undo` counted a 404 as deleted (a journal run against another Management Center "deleted" everything and renamed the journal), and the manual said that changed objects are kept, which they are not | the journal names its host and domain and is refused elsewhere; what is gone is said to be gone; the manual says what a delete by id does |
| medium | With a server that hid an object from the list and passed over it in the bulk call, the loader took the old object for its own, used it in the rules and deleted it on undo | ids are taken from the answer of the creating call; anything else is only the run's when it was not there before and says what was sent, otherwise the run stops and leaves it alone |
| medium | The answer to the rules call was not looked at: 15 of 18 rules created, "created with 18 rules" | the rules are listed afterwards and compared, number and order |
| low | Tracebacks of the loader: a `--cafile` that is none, a host with a space, an answer that is not HTTP, no password and no terminal, a policy or a journal that was edited | one line each; an edited policy is checked before anything is done, and can only post objects where objects go |
| low | Zones were matched with their case and objects without; a zone name an interface group has was found out after two zones were created | a zone that exists in another case is used; the interface groups are listed first |
| low | `RecursionError` in a conversion for groups nested about a thousand deep, or in a ring of that length | groups nested more than 64 deep are not converted, for every source |
| low | An encrypted zip given without `--from` got the general "compressed" message; an empty zip was taken for FortiOS | a zip is looked into, and the message says what is wrong with it |
| low | A Device Manager input without its interfaces and zones (FWShift's own import file read back): each interface of a NAT rule became a zone of its own, without a finding | read for any zone, `NAT_INTERFACE` at review level |
| low | Time: the journal was rewritten for every object (55 s for 4,000), the Device Manager emitter was quadratic in port objects (34 s for 10,000 rules), a listing could go on for ever, a zip unpacked to 500 MB was read | per call; an index (5,000 rules in 6 s on a shared CPU); 5,000 pages at most; 128 MB |
| low | A port object of a Device Manager with an empty port was every port, one without the field made the rule unusable; `"any"` as a port was every port | all three make the object unusable |
| nits | `PERMIT` for a Management Center and `ALLOW` for a Device Manager were taken; an unknown section was mandatory without a note; a holder with nothing but a type inside another was "nothing"; ping with code 0 could not be written for a Device Manager; a second undo said "deleted" | each manager its own words; `RULE_SECTIONS_UNKNOWN`; a type further in is content; written as the type alone (`ICMP_CODE`); fixed |

Not changed: a blocking rule that names protocols 4 and 41 next to others
is left out whole for a Device Manager (the reviewer: "worse than it
sounds"; it is now said in the manual and on the to-do list); `--policy` is
ignored for sources that have no such thing, like `--vsys`; a zone map that
merges two zones widens a rule between them without a note (older than this
release, on the to-do list).

The reviewer also went through the helpers the tests stand on. What it named
and what was done: the reader of emitted output skipped the name check for a
source of the same kind (a test of its own now), and did not keep ICMP codes
(it does); the made-up Management Center accepted any name, any value and a
blocking rule that logs at the end (it refuses them now), always answered in
full (it can now answer badly after carrying a call out, hide an object from
a list, pass over existing names, drop or reverse rules), and has interface
groups. Open: the made-up device of the tests has no ICMP codes and no
protocols 4 and 41, does not translate (packets name real addresses), and
the round trip between managers is compared with the model the project's own
parser read.

The fixes were not reviewed again. They have tests (the last sections of
`test_cisco.py`), and the suite, the mutation check and the type check were
run on them.

**Verified, and not**

* The tests: `tests/test_cisco.py` holds 437 tests, the suite
  2283. A mutation check with 67 ways to break the parser, the emitter
  and the loader was run before the review: 66 were caught, the one that was
  not (prefilter rules in the order of the file instead of their index) has a
  test now. The fixes of the review got a check of their own, 28 ways to
  take a fix back out: 27 were caught, and the one that was not was a line
  of the loader that did nothing (it is gone).
* **Nothing was run against a Management Center or a Device Manager.** The
  script has only talked to the stand-in of the tests and to the reviewer's;
  no import file was imported. The stand-ins are written from the same
  documentation as the code.
* The largest unknowns, in the order they would hurt: that rules created in
  bulk keep the order of the list (the script now checks, as long as a list
  of rules is in the order of the policy); how a real Management Center says
  that a policy inherits (the reader takes three forms and reports when it
  sees none); the names of the NAT containers of a Device Manager and the
  numbers behind its protocol and ICMP names (a wrong container name makes
  the import of NAT rules fail; a wrong number would read or write another
  protocol); whether a Management Center folds the case of names and shares
  them between zones and interface groups (the script assumes both, which is
  the cautious side); what a Management Center says to a name with a colon
  or a space (FWShift writes neither, except names it read from one).
* Application, URL, user and time conditions are not converted: such rules
  are written disabled, or left out for a Device Manager. Intrusion and file
  policies are reported and not written, also from a manager to a manager of
  the same kind.
* Not read: SSL, identity and DNS policies, platform settings, object
  overrides per device, routes. A cloud-delivered Management Center logs in
  another way than the script does.

### 2026-10-12: version 0.8.0

**Built**

* pfSense, read and written: `parsers/pfsense.py` and `emitters/pfsense.py`,
  as the format `pfsense`. Detected by the first element, `<pfsense>`.
* Read: the configuration backup (`config.xml`) of pfSense 2.6 and later, CE
  and Plus. Interface rules, rules of interface groups and of the groups
  pfSense makes itself (OpenVPN, IPsec, L2TP, PPPoE), floating rules quick
  and not, in, out and both, in the order pfSense evaluates them, which
  depends on its version; aliases of hosts, networks and ports, nested; the
  networks and addresses of interfaces with their virtual IPs, *This
  Firewall*; port forwards with NAT reflection and their filter rule
  association, 1:1 NAT, outbound NAT in its four modes; the rules pfSense
  adds for *Block private networks*, for port forwards that pass by
  themselves and for automatic outbound NAT. `--interface-address` gives the
  address of an interface that has none in the file (DHCP, PPPoE, SLAAC).
* Written: the areas Aliases, NAT and Firewall Rules of a configuration, for
  a restore under *Diagnostics > Backup & Restore*, for pfSense 2.7 and
  later. A rule per arrival interface; with `--zone-network` a rule for a
  destination zone is kept to it, as for an ASA (the code of the ASA
  emitter is shared); a leading deny for traffic that leaves becomes a
  floating rule; a rule that passes to any address leaves the firewall
  itself out; port forwards, 1:1 rules and manual outbound NAT.
* OPNsense is refused with a reason: it was planned with pfSense "where the
  two agree", and they agree less than expected (aliases, automatic rules
  and parts of NAT live elsewhere).
* `--interface-address` for any other source is an error; so is a second
  address of one IP version for one interface.
* A sample, `pfsense_sample.xml`, with its conversions to every target, its
  audit and matrix, and the conversions of the other eight samples to
  pfSense.

**What the platform made necessary**

* *The order is pf's, and the version decides it.* Floating rules first,
  then groups, then the interface; floating rules that are not quick decide
  last, the last one; group rules that share an interface are taken in the
  order of the file up to 2.7.2 and group by group after it.
* *Rules for what leaves are looked at after outbound NAT.* Read: a floating
  rule that blocks what leaves becomes a rule from every zone to that zone,
  ahead of the rest, and names the source after translation only where
  nothing is translated; one that passes what leaves decides nothing for
  forwarded traffic. Written: such a rule names a source only where the file
  decides outbound NAT, or else the report says so.
* *Rules see the translated destination.* As for FortiOS and Sophos: read
  rules are rewritten to the model's pre-NAT addresses, written rules to the
  translated ones, for the translations that are really written.
* *pfSense adds rules of its own.* Those that change what a policy lets
  through and are in the configuration (*Block private networks*, port
  forwards that pass, automatic outbound NAT) are converted as rules; the
  others are named.
* *Interface rules are also the rules for the firewall itself.* Other
  platforms filter forwarded traffic apart from what goes to the firewall:
  their "to any" leaves the firewall out when written for pfSense.
* *One protocol per rule, no service objects.* A rule per protocol, port
  aliases whose names cannot be taken for a service name.
* *A restore replaces an area.* The output is one file for three restores,
  and the report says what each takes along.

**Sources**

The source code of pfSense: RELENG_2_6_0, RELENG_2_7_2 and the development
branch (commit 9363ac5), above all `filter.inc` (what a rule becomes for
pf), `util.inc`, `interfaces.inc`, the edit pages of rules, aliases and NAT,
and `diag_backup.php` with `restore_config_section()`; the ICMP type names
of pfctl. Nothing was run on a pfSense, and no pf ruleset was loaded. The
judge in `tests/helpers.py` is written from the same reading of the same
code, apart from the parser.

**Review**

*Round 16* by the independent reviewer, with repro scripts of its own and
about 6,000 mutation-fuzz runs through the parser and four emitters, all
eight samples converted to pfSense, and the source code of all three
pfSense versions. 3 high, 8 medium and 8 low findings; in five of them the
judge of the tests made the same mistake as the code.

| | Finding | Fix |
|---|---|---|
| high | A floating rule that blocks what leaves, with a source, was written without a NAT area: the firewall keeps its own outbound NAT (automatic on a stock pfSense), translates the source first, and the rule never matches | written for the arrival interfaces where the networks of every zone are known; otherwise a floating rule with `FLOATING_AFTER_NAT` at review level. A test restores onto a firewall with automatic outbound NAT |
| high | Rules of platforms that filter only forwarded traffic opened the firewall itself: an iptables `FORWARD` rule for port 443 became `pass ... to any port 443` on WAN, the web interface included, "exact" | a rule of another platform that passes to any address is written for "any but This Firewall" (`SELF_EXCLUDED`) |
| high | Ports given as service names (`ssh`, `https`), which pfSense takes, made the rule "not loaded" | read by a table of service names; a name not in it makes the rule unusable, not unloaded |
| medium | Port forwards and 1:1 rules on an interface group or on OpenVPN, IPsec, L2TP, PPPoE were "not loaded" | read on the interfaces of the group or the system group |
| medium | A port alias forwarded to one numeric port was read as port to the same port | as `filter.inc` does it: all to that one port, unsupported (`several ports translated to the one port`) |
| medium | A virtual IP on a CARP address (`_vip<uniqid>`) was left out of the interface networks, *This Firewall* and automatic NAT | its parent's interface |
| medium | pfSense reads `opt` in an alias name in the source of outbound NAT as an interface (2.7.2: a ruleset that does not load) | such an alias is wrapped in another (`nat_set`) |
| medium | A floating rule without direction was read as `in`; pf has it for both | both |
| medium | The development branch keeps one table for both IP versions of an interface network (`not` of the version it lacks is every address); 2.6, and 2.7.2 for IPv6 of WAN and LAN, write `not` of a network with virtual IPs as a list that pf reads as every address | both by the version in the file; the second with `NEGATED_LIST` at review level |
| medium | Which interface has a gateway differed from pfSense (OpenVPN, IPsec, GIF, GRE), with NAT reflection on tunnel interfaces as a result; `NAT_AUTOMATIC_SOURCES` claimed tunnel networks were missing that were there | as `interface_has_gateway`; OpenVPN tunnel networks and the IPsec pool in automatic NAT, the finding for what is not in the file |
| medium | Aliases nested about 1,000 deep: a traceback | more than 64 deep is unusable, also for ports |
| low | Bridge members are separated by commas, and pfSense finds them by substring | as pfSense |
| low | No protocol and a port is `proto tcp` without a port; a range that runs backwards matches nothing; type and family are case-sensitive; 2.6 loads no floating rule on `any` | each as pfSense |
| low | Two interfaces with one description became one zone | a zone name of its own for the second |
| low | U+FFFE and other characters XML cannot hold reached the output | left out |
| low | Report texts: `MATCH_RULE_SKIPPED` said floating, `PFSENSE_RESTORE` did not say what a restore takes along; `--interface-address` was ignored for other sources and a second address replaced the first | fixed; both are errors |
| low | An outbound NAT rule without family and addresses is also IPv6 NAT | `NAT_IPV6_ALSO` |
| low | *This Firewall* is narrower than pf's `(self)` | in the manual |

Not changed: alias names that `/etc/services` or `/etc/protocols` hold are
not avoided (the web interface refuses them on the next edit, the restore
does not); leading spaces in values, which pfSense keeps; SCTP ports, which
2.6 ignores; whether `no rdr` and `no binat` reach further than their own
kind of NAT (a suspicion from pf, not checked). All four are on the to-do
list.

The judge of the tests was corrected with the code for service names, a
port and no protocol, floating rules without direction, virtual IPs on CARP
addresses and NAT on groups. The fixes were not reviewed again. They have
tests (the last section of `test_pfsense.py`, and an oracle that restores
onto a firewall with automatic outbound NAT), and the suite, the mutation
check and the type check were run on them; the check for `--interface-address`
with another source found that the option had been ignored there after all.

**Verified, and not**

* The tests: `tests/test_pfsense.py` holds 217 tests, the suite 2519. The
  parser is compared with the judge on random configurations (four versions
  and modes, 70 each, 300 packets each), NAT on 80, the emitter restored
  into the judge on 100 random models and on 30 more with automatic
  outbound NAT on the target, and the round trip pfSense to pfSense on 120.
  A mutation check with 14 ways to break the parser and the emitter, run
  after the fixes: all 14 were caught, three of them at first only by a
  golden file or not at all (service names in random rules, the last-match
  order of floating rules for what leaves, NAT reflection on a written 1:1
  rule); those have tests of their own now, and the judge refuses a 1:1
  rule with reflection.
* **Nothing was restored on a pfSense, and no pf ruleset was loaded.** The
  judge is written from the same reading of the same source code as the
  parser and the emitter, by the same hand; the reviewer read the code
  again, independently.
* The largest unknowns, in the order they would hurt: whether pfSense 2.8.0
  orders group rules as the development branch does (config 24.0 is read so);
  the names `getservbyname` knows; whether the restore of an area keeps
  references to aliases that are restored later (the manual says aliases
  first); what a restore does with a file written for 2.7 on a firewall
  with a configuration that pfSense upgraded since.
* Not converted: schedules, URL table aliases, policy routing, tags,
  limiters and shaping, match rules, IPv6 NAT, NPt, bogon networks, the
  captive portal, bridges, and the rules of packages and services.

### 2026-10-12: version 0.9.0

**Built**

* SonicWall, read and written: `parsers/sonicwall.py` and
  `emitters/sonicwall.py`, as the format `sonicwall`.
* Read: the settings export of SonicOS 6.5 and 7 (`.exp`, Base64 of
  URL-encoded pairs), or its decoded text. Address objects and groups,
  services and groups, zones and their security types, interfaces, access
  rules of both IP versions per pair of zones, NAT policies with interfaces
  as zones, reflexive policies. Objects SonicOS has by itself are worked out
  from the interfaces of the export (`X1 IP`, `X0 Subnet`, `LAN Subnets`,
  `Firewalled Subnets`, ...), default services from a table; the default rule
  of a pair of zones that has none in the export from the security types of
  its zones. `--interface-address` also for a SonicWall source.
* Written: commands of the SonicOS 7 command line. One rule per pair of zones
  and IP version with its place in the pair, groups for lists, the addresses
  that are left for a negation, a rule that denies at the end of every pair
  (SonicOS allows LAN to WAN by itself), NAT policies per pair of interfaces.
* A sample, `sonicwall_sample.exp`, written by `tests/tools/make_sonicwall_sample.py`,
  with its conversions to every target, its audit and matrix, and the
  conversions of the other nine samples to SonicWall.

**What the platform made necessary**

* *An undocumented format.* SonicWall documents how to decode the export and
  nothing of its keys. The parser reads what the published readers agree on,
  says so in a note, and treats every key a row does not have as unknown
  rather than as "any".
* *Rules per pair of zones, and defaults per pair.* The model's rules are one
  list; a SonicOS rule is for one pair. Read: rows of a pair in order, the
  default rule last. Written: a rule per pair, numbered within it.
* *Defaults that allow.* SonicOS lets LAN reach WAN with no rule. A policy of
  another platform denies that by default: every pair gets a rule that denies
  at its end.
* *One object per field, no negation, objects per IP version.* As for the
  Cisco managers and Sophos.
* *Objects of the firewall itself* (`X1 IP`) are in no export: worked out
  from the interfaces, and avoided as names when writing for a SonicWall.

**Sources**

SonicWall's knowledge base and documentation (decoding the export, the CLI
forms of objects, access rules and NAT policies, default access rules, zones,
NAT and its reflexive option), and three published readers of the export
for the key names. What comes from where, and what is assumed, is in the
table *Vendor behaviour the code relies on*.

**Review**

*Round 17* by the independent reviewer, with repro scripts of its own (about
40 hostile inputs through the command line). 5 high, 4 medium, 3 low:

| | Finding | Fix |
|---|---|---|
| high | A key a row did not have was read as empty, and empty is "any": a row with only an action became "allow any to any"; a missing `Enabled` was enabled, a missing interface of a NAT policy any | a key that is not there makes the rule unusable (written disabled, reported); an empty zone too |
| high | Nested service groups were written in the order of the model; a group before its member group lost that member, silently | groups after the groups in them; a member that cannot be written makes the group unusable |
| high | SonicWall to SonicWall: a group of SonicOS (`VPN Subnets`) inside a group was spelled out, and dropped when the export showed no interface of it | named, as SonicOS has it |
| high | A group that holds itself crashed the emitter | followed once |
| high | A zone with a space in its name was written without quotes: the commands that deny for it would be refused, and SonicOS's defaults apply | quoted |
| medium | `Port1 0` and `Port2 80` was read as ports 1 to 80 | port 80, as the readers show it |
| medium | An IPv6 rule that names an object of SonicOS got its IPv4 addresses | such a rule is unusable |
| medium | A priority of 5,000 digits: a traceback; 600 zones: 119 MB of output | a priority nobody can mean is none; more than 100 zones is an error that says why |
| medium | The version was not raised yet | raised |
| low | A default rule with a low priority number could stand before the rules of its pair; a NAT comment could end in a backslash; an FQDN was written without quotes | last of its pair; the characters left out; quoted |

Not changed: NAT policies are written in order without a priority (the
command is not known; the report says to check the order); the zone of an
address object is not read (SonicOS does not match by it). The judges were
corrected with the code where they shared a mistake (the place of the
default rule, `Port1 0`). The fixes were not reviewed again; they have tests
(the last section of `test_sonicwall.py`).

**Verified, and not**

* The tests: `tests/test_sonicwall.py` holds 153 tests, the suite 2693. The
  parser is compared with an independent reading of the export on 120 random
  exports (300 packets each), the emitter with the model on 60 random models
  on a firewall whose own defaults allow some pairs, the round trip on 30, the
  NAT of the emitter on 40. A mutation check with 12 ways to break parser and
  emitter: 11 caught, the twelfth changes nothing a packet can show (an ICMP
  rule written for IPv6 as well).
* **Nothing was run on a SonicWall.** The format of the export comes from
  third-party readers, the commands from knowledge-base articles; the judges
  are written from the same reading. NAT parsing has hand tests only.
* The largest unknowns: whether `priority manual N` is the command (without
  it SonicOS orders the rules of a pair by itself); which of the action codes
  0 and 1 is deny; how an export stores ICMP services, IPv6 and MAC objects;
  whether the default rules of a pair are rows of every export; the shape of
  a reflexive mirror.

### 2026-10-12: version 0.10.0

**Built**

* WatchGuard, read and written: `parsers/watchguard.py` and
  `emitters/watchguard.py`, as the format `watchguard`.
* Read: the configuration file of Policy Manager (Fireware 12). Interfaces
  as zones with their types, address groups, aliases (members that are an
  address at an interface, and other aliases), services, policies in the
  order of the file with their action and whether they are enabled, and the
  static NAT actions of their To lists as NAT rules of their own. A policy
  that names members of several interfaces becomes one rule per pair of
  From and To members. Automatic policy order is reported.
* Written: the policy part of a configuration file, to merge into one of
  the target: address groups, services, aliases of every zone and address a
  rule names, policies in manual order, and static NAT actions in the
  policies that allow exactly their traffic. Placeholders and disabled
  policies carry `FWSHIFT` in their description.
* A sample, `watchguard_sample.xml`, written by
  `tests/tools/make_watchguard_sample.py`, with its conversions to every
  target, its audit and matrix, and the conversions of the other ten samples
  to WatchGuard.

**What the platform made necessary**

* *An undocumented format.* WatchGuard publishes no schema and no sample of
  the file. The parser reads what three published readers agree on, says so
  in a note, and makes a policy unusable where an element it needs is not
  there (whether it is enabled, its service, an alias it names) rather than
  reading "any".
* *No zones, addresses at interfaces.* A member of an alias is an address
  and an interface together; the interfaces are the zones. A policy can
  name members of several interfaces on each side; the model's rule has one
  list of zones and one of addresses per side, so it becomes a rule per
  pair of member groups, which together match what the policy matched.
* *Automatic order.* By default the Firebox orders policies itself, by a
  cascade of how specific they are. That order is not worked out: the
  report says the file's order was read, and the output switches to manual
  order.
* *NAT inside the policy.* A static NAT action is part of the policy that
  uses it, so a NAT rule of the model can only be written into a policy
  that allows exactly its traffic, and is translated only there. Network
  dynamic NAT and 1-to-1 NAT are where none of the readers found them: not
  read and not written, and the report says so.

**Sources**

WatchGuard's Help Center (the file and how to get it, aliases and their
members, policy precedence and automatic order, unhandled packets, SNAT,
dynamic and 1-to-1 NAT, the default policies) and three published readers
of the file for the element names, read and never run. What comes from
where, and what is assumed, is in the table *Vendor behaviour the code
relies on*.

**Review**

*Round 18* by the independent reviewer, with repro scripts of its own
(hostile files through the command line, and the parser and emitter
against the judge). 5 high, 5 medium, 4 low:

| | Finding | Fix |
|---|---|---|
| high | A static NAT action was written into any policy for its public address, whatever its service, zones and sources: traffic the NAT rule did not translate was translated, and the reverse | only into a policy that allows exactly the NAT rule's traffic, which is enabled, allows, and has no other NAT rule before it; otherwise `NAT_NOT_IN_POLICY` |
| high | Read: one NAT rule for a static NAT action, for any source: the translation of one policy applied to traffic of others | one NAT rule per policy and source interface, with the sources, service and state of the policy |
| high | A user in the To list was dropped: the policy matched every user | the policy is unusable (written disabled) |
| high | Aliases that name each other many times over multiplied their members without end (memory) | members de-duplicated as they are read, and a cap on members in all, which is an error that says why |
| high | WatchGuard to WatchGuard: a policy naming the Firebox itself crashed the emitter (an assertion) | the Firebox is named as an alias, as Fireware has it |
| medium | Automatic order was taken to be off unless the flag said `1`; another value or no flag at all went unreported | anything but `0` is automatic, and a file without the flag is reported too |
| medium | An interface without a type took part in no class: `Any-Trusted` silently lost it | a member of a class is unusable when an interface of the file does not say its type |
| medium | `Firebox` as the interface of a member was read as no interface | it stands for every zone, as `Any` does |
| medium | A static NAT action named directly in the To list, not inside an alias, was not found | found both ways |
| medium | A policy with many members on both sides became thousands of rules | more than 1000 pairs makes the policy unusable |
| low | An ICMP member without a type was ICMP of any type; port 0 alone and protocol 0 were written as "every port" and "every protocol"; two objects of one name, the later one won; a policy and its rule in `policy-list` that disagree were not noticed | unusable; not written, and the rules that use them disabled; an error; the policy is unusable |

The judge was corrected with the code where it shared a mistake (a static
NAT member matches whatever interface the traffic leaves by). The fixes were
not reviewed again; they have tests (the last section of
`test_watchguard.py`).

**Verified, and not**

* The tests: `tests/test_watchguard.py` holds 105 tests, the suite
  2821. The parser is compared with an independent reading of the file
  on 80 random configurations, the emitter with the model on 60 random
  models, the round trip on 30. A mutation check with 12 ways to break parser and
  emitter: all 12 caught.
* **Nothing was opened in Policy Manager or loaded on a Firebox.** The
  format comes from third-party readers, one of which works from a sample it
  generated itself; the judge is written from the same reading. NAT has hand
  tests only.
* The largest unknowns: whether Policy Manager accepts a file merged from
  these lists, and the words it writes for the action of a policy; where the
  file keeps dynamic NAT, 1-to-1 NAT and the NAT settings of a policy; the
  codes of interface types (one reader); where `auto-order-enabled` sits.

### 2026-10-12: version 0.11.0

**Built**

* Barracuda CloudGen Firewall, read and written: `parsers/barracuda.py` and
  `emitters/barracuda.py`, as the format `barracuda`.
* Read: saved answers of the REST API of the firewall (8.0 and later), one
  after the other: the forwarding rules and the network and service objects
  they name. Rules of both IP versions, first match; pass, block and deny;
  deactivated; bi-directional rules as two rules; the interfaces of the
  entries of a source object as zones, a rule per interface; excluded entries
  subtracted; references between objects; TCP and UDP with client ports,
  ICMP, IP protocols.
* Written: a shell script of curl calls to the same API. Objects; then every
  rule, deactivated, at the top of the list, last rule first; then the rules
  that are to be active are activated, first rule first, so that a refused
  call leaves only the start of the policy active. Zones as the interfaces of
  source entries or as networks; a rule that blocks the rest, deactivated.
  `DRY_RUN=1` prints the calls.
* A sample, `barracuda_sample.json`, written by
  `tests/tools/make_barracuda_sample.py`, with its conversions to every
  target, its audit and matrix, and the conversions of the other eleven
  samples to Barracuda.
* Names are told apart without regard to case where a target asks for it
  (`sanitize_names(fold_case=True)`); a lone UTF-16 surrogate in any JSON
  input is an error instead of a traceback when the report is written.

**What the platform made necessary**

* *No export.* The configuration backup of a CloudGen Firewall (PAR, PCA,
  PGZ) is in a format of its own that Barracuda does not document, and
  Firewall Admin copies rules only between its own windows. The REST API is
  the one way out a program can read, and the one way in: input and output
  are both JSON of that API, documented by examples only. What is not in an
  example is assumed, and listed.
* *No zones.* A rule names addresses; the way out is the routes. The
  interface of an entry of a source object is the only interface a rule
  matches, and becomes the zone. Written, a zone is that interface or the
  networks behind it.
* *A list that is already there.* The script cannot replace the rules of the
  firewall, only add to them: its rules go above, its rule that blocks the
  rest is deactivated for a person to switch on, and rules are activated in
  order so that a stop half way never leaves an allow without the blocks
  above it.
* *NAT in the rule.* Dst NAT and Map are actions, source NAT a connection
  object, in a JSON no example shows: not read and not written, and said so.

**Sources**

Barracuda Campus (REST API, access rules, actions, bi-directional rules,
cascading rule lists, network, service and connection objects, the CSV import
of network objects, backup and restore) and the examples in its integration
articles; a published MCP server for the API for the keys of a rule, read and
never run. What comes from where, and what is assumed, is in the table
*Vendor behaviour the code relies on*.

**Review**

*Round 19* by the independent reviewer, with repro scripts of its own (14,508
mutated inputs through the parser and three emitters, a fake curl that
refuses a call). 2 high, 7 medium, 9 low:

| | Finding | Fix |
|---|---|---|
| high | The script created rules active, last first, and stopped at the first refused call: a later allow could be active without the blocks above it | rules are created deactivated and activated first rule first; the report says what a stop leaves |
| high | Names were told apart by case when written and not when read: an object `ANY` became a reference the firewall, and FWShift itself, take for the object Any | names are told apart without regard to case when written; read, only `Any` is Any, and an object of that name in the input wins |
| medium | Every rule made its own copy of the addresses of an object it needed by IP version or interface: 3 MB of input took 3 GB | a group per object, interface and IP version, made once |
| medium | A lone UTF-16 surrogate in JSON gave a traceback when the report was written (every JSON source) | an error that says why |
| medium | A user condition not spelled as a reference was read as any user; `bidirectional: 1` as one-way | read strictly, otherwise the rule is not used |
| medium | A bi-directional rule whose destination names interfaces: the way back was read for every interface | not used |
| medium | A rule that expires was converted as permanent, reported as information | an allowing rule that expires is not used; a blocking one is approximated |
| medium | Keys inside the protocol settings of a service entry were not checked; a null at the top hid client ports below | checked, and two values of one key are refused |
| low | ICMP limits were a note only; a service group naming a missing service went unreported; an interface `0` or `[]` read as none; the range shorthand `192.168.50-100` read as a host name; generated rule names could collide with names of the input; IP protocol 6 written without ports; ICMPv4 written into IPv6 rules; destinations an ASA worked out from its routes needed networks; the codes were not documented, curl hid the answer of a refused call and the token was visible to `ps` | on the rule; reported, and the rule not used; refused; refused; made unique; TCP with every port; only into the rule of its version; taken as they are; documented, `--fail-with-body`, the token in a file |

The judge was corrected with the code where it shared a mistake (the way back
of a bi-directional rule with interfaces; `"false"` as a flag). The fixes
were not reviewed again; they have tests (the last section of
`test_barracuda.py`).

**Verified, and not**

* The tests: `tests/test_barracuda.py` holds 181 tests, the suite
  3027. The parser is compared with an independent reading of the
  answers on 100 random inputs, the emitter with the model on 60 random models
  in two ways (zones as interfaces, zones as networks), the round trip on 30.
  The script itself runs in `sh` against a fake curl. A mutation check with
  12 ways to break parser and emitter: all 12 caught.
* **Nothing was run against a CloudGen Firewall.** The keys come from the
  examples in Barracuda's documentation and one published tool; the judge is
  written from the same reading.
* The largest unknowns: the JSON of a service object and its entries; whether
  `ipVersion`, `bidirectional`, the action `pass` and `deny` and `excluded`
  are spelled so; the limits of names; whether the API resolves names with
  regard to case; what `expand=true` holds for rule lists; the JSON of Dst
  NAT, Map and connection objects.

### 2026-10-19: version 0.40.0

**Per-vendor gaps: IOS and Huawei; a review of the lab.** IOS output names the right interfaces for the NAT of a
published host, FWShift reads IOS and Huawei output back for `convert --compare`, and the lab's Catalyst 8000V gets
the NAT the output leaves as comments. An independent review of today's lab work (0.37.0 to 0.40.0) found ten points;
what it found is fixed, and tier 3 on Google Cloud is held back until the firewalls' interfaces are written its way.

**Fixed**

* IOS target, NAT: the notes that say which interfaces are `ip nat inside` and `ip nat outside` took both from the NAT
  rule's zones. For a published host (destination NAT, written as `ip nat inside source static` with the host's
  address) the source's NAT rule has the outside on both ends (PAN-OS matches it before the translation), so the note
  put the outside zone's interfaces inside: loaded as written, the translation would not have worked. The inside is now
  the zone of the host's own address (from `--zone-network`, or the source's interfaces and routes; "the interfaces
  toward ADDRESS" where no network holds it), the outside the zone the connections come from. Golden files of the IOS target with destination NAT updated:
  only those notes changed.
* Lab, Catalyst 8000V: since 0.37.0 the lab policy has NAT, which the IOS output leaves as comments, as it leaves the
  zones; the session put in the zones only. It now puts in the NAT commands and each interface's `ip nat inside` or
  `outside` from those notes (`ios_nat`), and the 8000V's conversion gets the zones' networks.

**Fixed after the review**

* Google Cloud delivers through each subnet's gateway, not to a neighbour found by ARP (tier 1 found it for the test
  hosts); the firewalls' zone interfaces were set as `/24` on the link, as on AWS and Azure, and would not have reached
  the hosts: every run there would have failed. Not written for any vendor yet: a run on Google Cloud now stops
  before it starts anything (`CloudImage.open_point`), unless `--untested`; `lab.py list` and `lab/README.md` say
  "image found, not ready". (0.39.0 called the four images scripted.)
* The lab's IOS read-back against the output counted no difference: the zones FWShift reads there are `FWS-inside`
  and so on, the lab's `inside`; the lab's zones are now taken as the export names them, for both comparisons. A
  zone pair taken out of the router's configuration is now seen (a test).
* The ASAv's Day 0 gave the run's key to `admin`, also on Azure, where the lab logs in as the VM's user: it names
  the vendor's user now (`{user}`; `admin` on AWS, as before).
* Check Point on Azure and Google Cloud: the version in the first-boot data is taken from the image's name as those
  clouds name it (`check-point-cg-r82`, `check-point-r8210-...`: R82, R8210, as CloudGuardIaaS writes it), after the
  image is found; it was always R82.
* A flow to a published address is planned only where the publishing NAT rule is the one that decides it (its
  sources, and no rule before it): another policy could have given a wrong NAT FAIL. And a published address that
  answers without saying who it is, where the plan asserts the host that should answer, is a NAT FAIL (every run's
  hosts have the probe that says it: what answered was something the translation should not have reached).
* The read-back never ends a run: any error of it is its line in the summary; after Ctrl-C a run of tier 3 goes
  straight to its teardown, without the diagnosis and the read-back.
* FortiGate on Azure: the admin the custom data gives the run's key gets the super_admin profile (FortiOS makes no
  admin without one, should Azure not have made the user).
* Google Cloud's reserved addresses are among the leftovers a teardown looks for.
* DEVELOPMENT.md, 0.37.0: Check Point's hide NAT needs review (so it is not asserted there) and SonicWall's NAT is
  exact; the count of asserted flows is 127 of 129.

**Built**

* `convert --compare` reads IOS output back (`ios` among the targets read back): as if its interfaces were in their
  zones, the commented lines at its end switched on (`emitters/ios.activate`); its zones matched without the `FWS-`
  prefix, as RouterOS's.
* `convert --compare` reads Huawei output back too (its commands are read as FWShift reads a configuration; its zones
  matched without FWShift's own prefix): of the sample's own conversion, one possible difference (a schedule compared
  by name).
* The lab's read-back compares the Catalyst 8000V's running configuration with the output as loaded, too (IOS among
  the formats compared against the output; the lab's zones found without the `FWS-` prefix).

**Verified**

* Tests: the lab policy's NAT sides with and without the zones' networks; IOS output of the ASA sample read back by
  `convert --compare`, and Huawei output of the Huawei sample; `activate`; the 8000V session's NAT and interface sides; every dry run with the read-back.
* The suite (6,699 tests, on Python 3.13 and 3.9; mypy, on both, and pyflakes clean).
* **Not verified**: on a router (the next 8000V run of the lab).

### 2026-10-19: version 0.39.0

**Tier 3 on Azure and Google Cloud.** The lab's tier 3 runs on the Marketplace images of Azure and Google Cloud as
well as AWS's (`--cloud azure`, `--cloud gcp`), with the same plan, load, probes, diagnosis and read-back. Of the nine
vendors of tier 3, six are scripted on Azure and four on Google Cloud; the rest are not there, or not in a way the lab
can use yet, and the lab says why. Scripted from the vendors' own Terraform modules and guides; no run has been made
on either cloud.

**Built**

* Terraform modules `lab/tier3/azure` and `lab/tier3/gcp`: the firewall with a management NIC (public address, its
  ports from your address) and a NIC in each zone at `.4`, the published address as a second address (Azure) or an
  alias address (Google Cloud) of the outside NIC, and the five test hosts as in tier 1. Azure: one resource group per
  run, a route table per zone subnet with the other zones through the firewall's NIC (a virtual appliance, IP
  forwarding on its NICs), the Marketplace plan, boot diagnostics; Google Cloud: four VPC networks (management and one
  per zone: each NIC of an instance in a network of its own), routes to the firewall's NIC in each, `can_ip_forward`,
  the first-boot data in the metadata the image reads.
* `run_cloud` in `tier3.py`: the image of the vendor on that cloud (`CloudImage`: Azure `PUBLISHER:OFFER:SKU`, its plan
  the same; Google Cloud an image, a family, or the newest image of a publisher's project whose name starts as given,
  for the publishers that name images by version), the vendor's differences there (the user, the first-boot data), the
  terms accepted on Azure, the console kept for a firewall that does not come up (`az vm boot-diagnostics
  get-boot-log`, `gcloud compute instances get-serial-port-output`), and a teardown that checks the cloud's own
  leftovers. The steps after the firewall exists are one function for the three clouds.
* The images: FortiGate (Azure PAYG 7.6 with the configuration as Fortinet's templates write the custom data, and the
  run's key for the VM's user; Google Cloud the PAYG family of 7.2), VM-Series (Bundle 1 on both), vSRX (Azure PAYG),
  Catalyst 8000V (Azure BYOL), ASAv (BYOL on both, Day 0 in the custom data or the startup script), Check Point (Azure
  R82 PAYG, Google Cloud R82.10 PAYG standalone, with the first-boot data CloudGuardIaaS writes for each). Not on a
  cloud, or not usable yet, with the reason (`NOT_ON`): the vSRX and the Catalyst 8000V on Google Cloud (image projects
  not found), pfSense Plus and OPNsense on Azure (plans not found; several NICs), SonicWall on Azure (BYOL only), and
  pfSense, OPNsense and SonicWall on Google Cloud (not offered).
* `lab.py run tier3 ... --cloud`, `--cloud-image`; `lab.py list` and `lab/README.md` show every vendor on every cloud;
  `lab.py destroy` tears a run down on its own cloud.
* The Catalyst 8000V's Day 0 names the vendor's user ({user}), which on Azure is the VM's.

**Verified**

* Every scripted vendor on Azure and Google Cloud, dry (`tests/test_lab.py`): the conversion, the plan, the
  variables against the module of that cloud, the order of the commands, the first-boot data, the read-back of the
  dry run; a vendor that is not on a cloud is refused with the reason.
* The suite (6,694 tests, on Python 3.13 and 3.9; mypy, on both, and pyflakes clean).
* **Not verified**: any run on Azure or Google Cloud (Terraform not run either: the modules are checked against their
  variables, not planned); the images' names where the vendors' sources are old (the vSRX on Azure, 2022) or give only
  an example (the 7.2 FortiGate family); the first-boot formats on those clouds.

### 2026-10-19: version 0.38.0

**The read-back.** After the probes, every run of tiers 2 and 3 exports the policy as the firewall holds it, reads it
with FWShift and compares it with what was loaded and with the source. Through the Linux kernel, for nftables and
iptables, the firewall holds the ruleset as loaded, and decides as the source but for the published port, which the
conversion report announced.

**Built**

* `lab/readback.py`: the export written as `export.*`, read by FWShift, and two comparisons (`fwshift compare`, as
  JSON): with the converted output, where FWShift reads its own output back (FortiOS, PAN-OS, Junos, ASA, nftables,
  iptables), and with the source (the lab's zones aligned to the names the export has: the conversion's zone map, the
  interface descriptions of pfSense and OPNsense). Only differences between two of the lab's zones count; certain and
  possible ones apart. `readback.txt` holds both, the summary a line (`read-back ...`) before its result, and
  `summary.json` the counts (`readback`). An export FWShift cannot read, or reads no rule from, is "not read", with
  the reason; the read-back never changes the run's result.
* The exports. Tier 2: `nft list ruleset` and `iptables-save` in the firewall's namespace, RouterOS `/export`, the
  `config.xml` of pfSense and OPNsense. Tier 3: FortiGate `show` of the zones, objects, VIPs, IP pools, central SNAT
  and policies (the `config ... end` blocks of the session); VM-Series `show` in configure mode in `set` format; vSRX
  `show configuration | display inheritance no-comments | display set | no-more` (its `set` lines); Catalyst 8000V and
  ASAv `show running-config`; pfSense Plus and OPNsense `/conf/config.xml`; Check Point the Management API's
  `show access-rulebase` of every layer, `show nat-rulebase` and `show access-layers` (the manual's export, one JSON
  array). SonicWall: not read (the settings export FWShift reads is made in the web console only). Tier 1: not yet.
* In a dry run the export is what was loaded (the merged `config.xml` for pfSense and OPNsense), so every dry run
  goes through the read-back too.

**Verified**

* Through the Linux kernel, for nftables and iptables (`tests/test_lab.py`): the read-back of a real run, no
  difference from the ruleset loaded, one certain difference from the source (from the outside to the web server
  on port 8080: `NAT_PORT_TRANSLATION`); an export with a rule taken out shows a certain difference against the output;
  an export with no rule, an empty one, a failing export: "not read", and the run goes on.
* Every dry run of tiers 2 and 3: the read-back's line, and against the output no certain difference.
* The suite (6,681 tests, on Python 3.13 and 3.9; mypy, on both, and pyflakes clean).
* **Not verified**: the exports on the devices (their commands are from each vendor's documentation and the
  manual's own export instructions); tier 1.

### 2026-10-19: version 0.37.0

**NAT in the lab.** The lab policy hides the inside behind the firewall's outside address and publishes the web server
on the outside, and every run checks what NAT did as the hosts saw it: which address a connection came from, and which
host answered the published address. Through the Linux kernel the hide NAT and the published server went as the source
has them, for nftables and iptables; a ruleset without the hide NAT, or one that hides what it should not, fails.

**Built**

* The lab policy (`lab/policy/lab_panos.xml`): the NAT rules `web-publish` (from the outside, 10.20.3.100 port 8080
  to the web server dmz10 port 80) and `inside-hide` (the inside network, to the outside, behind the address of the
  outside interface), and the security rule `outside-web-published` that lets the published service in. Synthetic
  addresses only, as before.
* The probe answers with its own address and the address the connection came from as it saw it (TCP: a line after
  the handshake; UDP: the answer); `probe.py send` reports them as `answered_by` and `seen_as` for a flow that passed.
  sshd on port 22 says nothing, and a probe of before answers without them (`unseen`).
* The plan (`labplan.build_plan`, with the firewall's own address per zone: `.1` in tier 2, `.4` in tier 3; none in
  tier 1): for each flow that should pass on a port the probe answers, the address the receiving host should see
  (`seen_from`): the source's, or the firewall's in the zone the flow leaves by where the first NAT rule that matches
  it (zones, addresses through the policy's objects, service) hides it behind the interface. One flow more in tiers
  2 and 3 for each address the source publishes, from the zones it is published to (out10 to 10.20.3.100:8080): its
  security verdict from the rule for the translated address's zone, the host that should answer (`answered_by`). What
  NAT does is asserted (`nat_asserted`) when the deciding NAT rule was converted exactly, or with findings that only
  widen where it applies (`NAT_INPUT_INTERFACE`: whatever input interface; `NAT_ZONES`: whatever zones), and no rule
  widened that way could match the flow instead; apart from whether the flow passes, which stays the flow's verdict.
* The check: a NAT mismatch on an asserted flow is `FAIL` (and fails the flow), on another `differs-announced`; the
  summary counts them (`NAT:`) and shows each mismatch with the NAT rule. A dry run fakes the answers the plan expects.
* Routing to the published address: tier 2 routes it from the hosts of its zone to the firewall (`/32` via `.1`);
  tier 3 gives the firewall's interface in that zone it as a second address (`published` of the AWS module, in
  order after `.4`, which stays the primary one).
* Conversion options for NAT in tier 3: Check Point `--target-gateway fwlab-cp` (the hide NAT names the gateway
  object; the script puts in the name the run found), SonicWall `--interface-map` for the PAN-OS interfaces (X0 inside,
  X2 dmz, X3 outside), and the VM-Series `--interface-map` too: its zones are on ethernet1/1 to 1/3 in the order of
  AWS's cards (inside first), where the source has the outside on ethernet1/1, and the hide NAT takes the address of
  the interface it names. pfSense and OPNsense keep pf's NAT rules in `load.txt` (`pfctl -sn`).
* `lab.py plan` lists the flows whose NAT is not asserted, with the reason.

**What the conversions say of the lab policy's NAT**

* FortiOS, PAN-OS, Junos, IOS XE, ASA: both NAT rules exact.
* nftables, iptables, pfSense, OPNsense, RouterOS: `inside-hide` approximated with `NAT_INPUT_INTERFACE` (written for
  every input interface; the translation of the inside's connections is the same, and the dmz's connections leave
  by the dmz, which the rule does not name: all asserted).
* Check Point: `web-publish` approximated (`NAT_ZONES`: written without zones, which only widens it); `inside-hide`
  behind the gateway with `--target-gateway`, needs review (`NAT_ZONES`: without zones it would translate traffic
  toward the dmz too), so the hide NAT is not asserted there. (Corrected in 0.40.0: this said both less.)
* SonicWall: both exact, with `--zone-network` and `--interface-map`. (Corrected in 0.40.0: this said `web-publish`
  needed review.)
* AWS, Azure, Google Cloud: not converted (`NAT_NOT_CONVERTED`): the clouds' NAT is the gateways'. Tier 1 asserts
  that no address is translated and publishes nothing.
* On targets that look rules up after NAT (nftables, iptables, and the others but PAN-OS), two security rules are
  now reported: `outside-web-published` (`NAT_DESTINATION_REWRITTEN`, and `NAT_PORT_TRANSLATION`: its service still
  names port 8080), and `outside-web` (`NAT_ADDRESS_EXPOSED`: after the translation, traffic to the published address
  matches it too). The flows they decide (out10 to the published address, and out10>dmz10:tcp/80) are no longer
  asserted there: 127 of the 129 flows through the firewall asserted (128 of 128 before, without the published one).

**Verified**

* Through the Linux kernel, for nftables and iptables (`tests/test_lab.py`): 127 asserted flows and the two
  unasserted ones as the source decides; the inside seen by out10 as 10.20.3.1, the dmz's own addresses unchanged,
  out10's connection to 10.20.3.100:8080 answered by dmz10 and seen from out10's own address. Without the hide NAT the
  run fails (`in10>out10` seen from 10.20.1.10); with a hide NAT on the dmz instead, too (the published server's client
  seen from 10.20.2.1).
* Every run of every tier dry, with the NAT expectations, the published address in the AWS variables and the route
  in tier 2.
* The suite (6,679 tests, on Python 3.13 and 3.9; mypy, on both, and pyflakes clean).
* **Not verified**: the NAT on any device of tier 3 or VM of tier 2: the next run of each tests it.

### 2026-10-19: version 0.36.4

**The pfSense and OPNsense output loaded on pfSense Plus and OPNsense.** The lab's tier 3 runs pfSense Plus, OPNsense
and the SonicWall NSv from the AWS Marketplace and finds every image and instance type by itself; pfSense Plus passed on
its sixth run and OPNsense on its first full one, the seventh and eighth firewalls of tier 3 to pass. The runs before
them found faults of the lab only, none in FWShift's output.

**Built**

* Three more images in tier 3. **pfSense Plus** (Netgate) and **OPNsense**
  (Deciso's image): the image's `/conf/config.xml` is read over SSH, the areas of the conversion put in (tier 2's
  merge) and the zones put on the data cards (OPT1 to OPT3 on ena1 to ena3, the lab's addresses, no blocking of private
  networks; an interface the image had on one of those cards is taken out; WAN, the first card, by DHCP, stays for
  management), written back, and the firewall rebooted; ready again once ena3 has its address, loaded once pf has a
  rule for the lab's web server. Commands are given to ssh (pfSense's `admin` gets the console menu with a terminal);
  OPNsense's `ec2-user` uses sudo. **SonicWall NSv**: `admin` with the instance id as the password (SonicWall's AWS
  guide), given by SSH_ASKPASS (OpenSSH 8.4 and later; without BatchMode, which ssh would keep as the first value), and
  SonicOS's own `User:` and `Password:` answered in the session (paced typing now answers questions before a prompt);
  the zones `inside`, `dmz` and `outside` made, trusted (a WAN zone adds NAT policies), and X0, X2 and X3 put in them
  (AWS's first card is X1 and the second X0, per SonicWall's guide; X2 and X3 are assumed), then FWShift's commands.
  pfSense's image is found by its name (`pfSense-plus-ec2-*-RELEASE-amd64*`, 26.07). Sophos Firewall is left out for
  now: its XML API is switched on in the web console only.
* Every image of tier 3 is found without `--ami`: names for each vendor (several, with a comma; Check
  Point and CloudGuard, OPNsense, SonicWall and NSv, `*vSRX*` and `*ASAv*` beside the old patterns), and of the
  products those names cover, the newest image of one the account is subscribed to. Each product (the newest image of
  each) is tried with `run-instances --dry-run`: `DryRunOperation` is subscribed, `OptInRequired` is not, anything else
  does not tell, and then the newest is taken; one product alone is not tried. The finds and the answers go to
  amis.txt.
* The instance type is found the same way, unless `--instance-type` says: the vendor's type, then others of four ENA
  cards (t3.xlarge, c6i.xlarge, m6i.xlarge, r5.xlarge, ...), each tried with the dry-run launch, which answers
  `UnsupportedOperation` for a type the product does not take; the first it takes is started (instance-types.txt). A
  try that does not tell keeps the vendor's own.
* The lab's own fixes from the pfSense runs: the Elastic IP attached once the instance runs; the image's WAN rules
  kept in the merge; pf's rules recognised by the alias table as well as the address (tier 2 too); the console saved
  when a load fails; the test hosts' probe waiting for its address, and sent compressed in their user data.

**Tested**

* The first pfSense run found its image by the name (26.07, product code `cphb99lr7icr3n9x6kc3102s5`) and
  stopped in Terraform: the Elastic IP was attached to the management interface while the instance was still being
  made (`IncorrectInstanceState`, "pending-instance-creation"); the earlier runs had won that race. The address now
  waits for the instance (`depends_on`), which Terraform makes once it runs. The second pfSense run got in (the key
  refused once, early in the first boot, then taken), read the image's configuration (pfSense Plus 26.07, config
  version 24.6, WAN on ena0 by DHCP and nothing else), wrote the merged one and rebooted; then SSH timed out for the 15
  minutes. The image lets SSH and HTTPS in on WAN by rules of its own ("Default SSH rule", "Default HTTPS rule"), and
  the merge replaces the rules as a restore does: the lab locked itself out. The image's WAN rules are now kept in
  front of the converted ones (pfSense's rules and OPNsense's legacy and own rule lists), and a load that fails saves
  the firewall's console as the boot does. The third pfSense run came back after the reboot with ena1 to ena3 on
  10.20.1.4, 10.20.2.4 and 10.20.3.4, and pf held the image's WAN rules and then every converted rule, in order, on
  ena1 to ena3; the run still stopped: the check looked for 10.20.2.10 in `pfctl -sr`, and pfSense holds aliases as
  tables (`<web_server>`). The check (tier 2's as well, which had never run for real) takes the address or the table.
  The fourth pfSense run loaded the policy and stopped before the probes: test host in11's probe had started before its
  test interface (attached after the host boots) had 10.20.1.11, every bind failed once with "Cannot assign requested
  address", and the host answered on nothing for 15 minutes. A race of the lab's own hosts, won by every run before.
  The probe now waits for the address (other bind errors, such as sshd's port 22, still end that listener). That
  made the probe 11 KB, and its base64 in the test hosts' first-boot script 17.5 KB of user data: AWS takes 16 KB, and
  the fifth pfSense run stopped in Terraform at every test host. The probe goes in compressed now (gzip, then base64,
  about 7.7 KB in all), and a test keeps the user data under 12 KB. The sixth run, by the author: **PASSED** (local
  32, ok 96, ok-unasserted 32), the seventh firewall of tier 3 to pass and the first device loaded with FWShift's
  pfSense output (the areas put into config.xml as a restore does, the image's WAN rules kept, then a reboot). What it
  took: the Elastic IP after the instance, the image's own management rules kept, the check by alias table, and test
  hosts that wait for their address.
* The first OPNsense runs found the image by its name (OPNsense 26.1.5, sold by OPNsense, product code
  `1a8db4k5vqv7gye9gt947sk94`); AWS refused c5.xlarge and then m5.xlarge for the product (`UnsupportedOperation`)
  before anything was started, which the instance type search now finds by itself. The next run, by the author, with
  an instance type the product takes: **PASSED** (local 32, ok 96, ok-unasserted 32) on its first full run, the eighth
  firewall of tier 3 to pass: the same load as pfSense (the image's WAN rules kept, the zones on ena1 to ena3, a
  reboot), with `ec2-user` and sudo.
* The suite (6,669 tests, on Python 3.13 and 3.9; mypy, on both, and pyflakes clean).
* **Not verified**: NAT on any device (the lab policy has none); a Check Point policy installed on a gateway; the
  SonicWall NSv of tier 3, the Check Point vendor of tier 3 and the VMs of tier 2, never run; the restore of
  pfSense or OPNsense areas in their web consoles.
* After the release, the first SonicWall NSv run: the image found among two products of the names by the subscription
  (`SonicWall_NSv_PAYG_8x2x2_R9870-...`, product code `3qvj5r0px8dqjhz6yz1w14psz`); SSH answered after the first boot
  and refused `admin`: "Only 'management' user is allowed to login". SonicWall's AWS guide says so: SSH as
  `management` with the key pair opens the NSv Management Console, and Ctrl+S then the spacebar switch to the SonicOS
  CLI, which asks for its own user and password (admin, the instance id). The lab now logs in as `management` with the
  run's key, sends those keys once the console is drawn (paced typing takes keys to send first; what came before them
  is not searched for the prompt), answers the CLI's login (escape codes after the question allowed), and closes a
  session that does not end after its last line (leaving the CLI goes back to the console). The second NSv run ended
  on its first ready try, the NSv still booting: ssh wrote its own error and exited, the keys for the console went to
  it, and BrokenPipeError ended the whole run (the run's state then had no `torn_down`). A session that ends before or
  while it is written to is now a try that failed, which the wait repeats, and its pipe is closed quietly. The third
  run: SSH as `management` answered after about ten minutes with the SonicCore console ("[Ctrl-s spacebar] to switch
  console"), which said "Please wait for SonicOS to startup ..." and "CPU configuration updated, will reboot in 10
  seconds". The ready check (`sonicos|firmware`) matched the word SonicOS in that text; the lab loaded, and the load
  met the reboot ("Connection timed out"). Ready now means fields only the CLI's `show version` answers
  (firmware-version, rom-version, serial-number, system-uptime), and the NSv is given 45 minutes to boot. The fourth
  run: after about 14 minutes the SonicCore console (SonicOSX 8.2.2-8015-R9870, "NSv M"), and after Ctrl+S and a space
  the CLI's prompt `NSv >`, no login asked; the lab never saw it: the console redraws its status bar ("SonicWall (c)
  2026 | [Ctrl-s spacebar] to switch console") after every output, with cursor codes, and writes its spaces as cursor
  moves, so the prompt was never last in what it wrote. A full-screen console is now read as plain text (labrun's
  screen_text: a cursor move right as spaces, the other escape codes left out, the vendor's noise pattern, the status
  bar, taken out) for the prompt, the questions, the ready answer and the refused lines; the session's own text is
  kept beside it (`load.raw.txt`). The ready answer is the CLI's form, lowercase and hyphenated (`firmware-version`),
  as the console's boot text has "Firmware Version :" and "Serial Number :". Not yet run further.

### 2026-10-18: version 0.36.3

**The IOS output loaded on a Catalyst 8000V.** The lab's 8000V passed on its third run, the sixth firewall of tier 3
to pass and the first device loaded with FWShift's Cisco IOS output; the runs before it found what the lab needs to
reach the router, nothing in the converted policy.

**Built**

* The lab, tier 3, the 8000V, with what the ASAv and vSRX runs taught: ready once `show ip interface brief | include
  GigabitEthernet` lists GigabitEthernet2 to 4 (filtered, for the pager); lines typed one at a time after the prompt; a
  2048-bit key; the router's own view kept after the probes (interfaces, zones, zone pairs with their sessions, routes,
  the configuration). The image is "Cisco Catalyst 8000V SD-WAN & Router - PAYG - DNA Essentials", named
  `Cisco-C8K-PAYG-ESS-<version>-<id>`; the lab looks for `Cisco-C8K-PAYG-ESS-*` (it had `Cisco-C8K-*`, which also
  matches the bring-your-own-licence and DNA Advantage editions).
* Day 0 configuration for the 8000V in its user data (Cisco's `Section: IOS configuration`): the run's key whole, as a
  `key-string` wrapped at 64 characters, for `ec2-user`, and `ip ssh server algorithm publickey rsa-sha2-512
  rsa-sha2-256 ssh-rsa`; ssh is given `PubkeyAcceptedAlgorithms=+ssh-rsa`. (`{ssh_key_lines}` in a vendor's user data:
  the key's base64 part, wrapped.)
* Every ssh and scp of the lab offers only the run's key (`IdentitiesOnly=yes`): an ssh agent's keys go first
  otherwise, and a device that allows three tries (IOS XE) can refuse the login before the run's key is tried.
* The first refused login of a run is followed by one `ssh -v`, whose lines about the login (the key offered or
  skipped, the server's answer, the signatures it takes) go to boot.txt.
* An image given with `--ami` that does not exist in the region stops the run before anything is made (it went on to
  Terraform, which failed).

**Tested**

* The first 8000V run, with `--ami`: the id was of another region (the subscription's launch page shows the id of the
  region chosen there); `describe-images` said so and the run went on to Terraform. Nothing was made.
* The second run found the image by its name (IOS XE 26.02.1, c5.xlarge, us-east-1) and booted it; SSH as `ec2-user`
  was refused for the whole boot, "Permission denied (publickey,keyboard-interactive,password)". Its console: IOS XE
  takes no ssh-rsa signature by default (`SSH_COMPLIANCE_SSH_RSA_DISABLED`, "from IOS-XE release 17.16.1 onwards"), and
  its own set-up (CVAC, from the instance's metadata) gave `ec2-user` the AWS key as an MD5 `key-hash`; every session
  was set up and every login failed at authentication. Two possible causes: a server that does not announce the RSA
  signatures it takes leaves OpenSSH none to use with an RSA key, and the lab's ssh offered an agent's keys first.
* The third run, by the author, with the Day 0 configuration and only the run's key: **PASSED** (local 32, ok 112,
  ok-unasserted 16): the converted zone-based firewall taken without an error, every connection through the router as
  the source decides. Which of the two fixes the login needed is not known from the result.
* The suite (6,649 tests, on Python 3.13 and 3.9; mypy, on both, and pyflakes clean).
* **Not verified**: NAT on any device (the lab policy has none); a Check Point policy installed on a gateway; the Check
  Point vendor of tier 3 and the VMs of tier 2, never run.

### 2026-10-18: version 0.36.2

**The Check Point output published and verified on a management server.** The converted lab policy ran as FWShift's
`mgmt_cli` script on R82.20, by hand; its first runs found two faults of the emitter, both fixed. The lab's tier 3 has
a Check Point firewall, scripted, not yet run.

**Built**

* The Check Point emitter adds `ignore-warnings true` to every `add`: a warning (a port or an address another object
  has already) refuses a call otherwise. Errors still stop the script.
* Every access rule writes its source, destination and service, `Any` where the source policy says any, and every NAT
  rule its six cells (`Any` for an original cell, `Original` for a translated one): a cell left out is stored as None,
  which matches nothing. The replay of the script in `tests/helpers.py` refuses a rule that leaves a cell out; tests
  `test_every_add_ignores_warnings`, `test_every_rule_fills_all_three_cells`, `test_every_nat_rule_fills_all_six_cells`.
  The 28 expected `*_to_checkpoint.sh` outputs differ by those words only.
* The lab's tier 3 got a Check Point firewall: the All-In-One image (gateway and management on one
  instance, pay as you go), by `--ami` (Check Point's own templates find it by a map of ids, not by a name), on an
  m5.xlarge (the management API may not start below 8 GB). Its first-time setup is the image's `/etc/cloud_config.py`
  as Check Point's Terraform module for a standalone calls it, with bash for `admin`; ready when `api status` reports
  "API readiness test SUCCESSFUL" (as Check Point's own scripts wait), up to 60 minutes. FWShift's `mgmt_cli` script
  and the lab's driver are copied over (scp) and run: the data interfaces' addresses (`clish`), the script in its own
  session, one `set simple-gateway` naming every interface (eth0 too, as it replaces the list) with each data
  interface in its security zone and anti-spoofing off, publish, install of `Standard`. It stops at the first failing
  step. Taken from Check Point's templates, the API reference as its Ansible modules spell it, and CheckMates; not
  confirmed: whether eth2 and eth3 get addresses of their own, the type of a standalone's object (the driver lists
  them), and whether `set simple-gateway` takes a standalone. Never run.

**Tested**

* The first Check Point output on a real management server: R82.20, a Security Management Server
  installed from the ISO in VirtualBox, by the author, with the converted lab policy run as FWShift's `mgmt_cli`
  script. Its first object was refused: `add service-tcp name tcp-ssh port 22` failed with `err_validation_failed`,
  "Validation failed with 1 warning", "The port is already used by another service" (the server's own `ssh`). A
  warning fails a call unless it is ignored, and the converted services repeat ports of predefined ones (TCP 80, UDP
  53) as converted hosts may repeat addresses. A fault of the emitter: every `add` now carries `ignore-warnings true`
  (accepted by every command the script uses, per Check Point's Ansible collection); errors such as a name taken
  still stop it. The manual says so. Run again with it: every call accepted ("Done."), the objects, the zones, an
  inline layer per pair of zones and their rules in the session. Published, SmartConsole showed None in every cell
  the script had left out where the source says any: the destination of guest-not-to-dmz and inside-out, the
  source of no-dns-out and outside-web, the services of the seven rules that apply a zone pair's layer, and all
  three cells of every FWShift cleanup rule; and "Missing cleanup rule" under each layer. None matches nothing:
  no traffic would have reached the inline layers. The emitter had assumed that a cell left out means Any, and so
  had the test helper that replays the script. A fault of the emitter: every access rule now writes all three
  cells, `Any` where nothing is named, and every NAT rule all six (`Any` for an original cell, `Original` for a
  translated one, which no server has shown yet). The replay in tests/helpers.py refuses a rule that leaves a cell
  out. The lab policy's script differs from the first only by those cells. Loaded again after the first run's
  objects were deleted and published: SmartConsole shows Any in every one of those cells, the seven zone-pair
  rules with their inline layers in the source's order, rule 8 the FWShift cleanup (Drop, Log) above the layer's own
  Cleanup rule, and no "Missing cleanup rule". `verify-policy policy-package Standard`: "Rules Verified OK!", no
  warnings, no errors. Not installed on a gateway: no traffic checked. README, manual, guide, lab README and TODO
  say so. A run that stops
  halfway leaves objects behind (`More than one object named 'inside-net' exists`): delete them and publish
  first.
* The suite (6,644 tests, on Python 3.13 and 3.9; mypy, on both, and pyflakes clean).
* **Not verified**: a Check Point policy installed on a gateway with traffic through it; NAT on any device (the lab
  policy has none); the Catalyst 8000V and Check Point of tier 3, and the VMs of tier 2, never run.

### 2026-10-18: version 0.36.1

**The ASA and Junos output loaded on an ASAv and a vSRX.** The lab's ASAv passed on its ninth run and its vSRX on its
fourth; the runs before found one fault of the converter and what each firewall needs of the lab.

**Built**

* The ASA emitter keeps object names clear of the ASA's own service objects ("cannot modify system-defined object":
  9.24 refused `object service tcp-ssh` and `tcp-http`, and the rules naming them would have used the ASA's objects):
  every `tcp-`, `udp-`, `tcp-udp-` and `sctp-` name with one of the ASA's port names, `icmp-` and `icmp6-` with one of
  its ICMP type names, for objects of every kind. Such an object is renamed (`tcp-ssh_2`, `RENAMED`); the manual says so.
* CI's mypy on Python 3.9 failed, after the release of 0.36.0, on `export.py` (a table of functions whose signatures differ, joined
  to an uncallable `function`); fixed by typing the table. The release check had run mypy from Python 3.13 with
  `--python-version 3.10`, which did not show it; it now also runs mypy as CI does, on the 3.9 interpreter.
* The lab, tier 3: a Day 0 configuration for the ASAv (management by DHCP, a host key, SSH on management, the run's
  key for `admin`, privileged at login, an enable password made for the run); a key size per firewall (2048 bits for
  the ASAv) and ssh settings per firewall (`ssh-rsa` for the ASAv); the wait ends at once when ssh and the firewall
  have no algorithm in common; a command that hangs keeps what it wrote; lines typed one at a time after each prompt,
  where a firewall needs it (`Runner.run_paced`); a session that answers almost nothing fails; the interface names
  read from the firewall (`ports.txt`); a session that ends early names the refused lines first; the firewall's own
  view after the probes (`diagnose.txt`, for the ASAv and the vSRX); every SSH try (`boot.txt`) and the console
  (`console.txt`, `console.jpg`) kept when the CLI never answers. The vSRX is ready once its forwarding engine has made
  the data interfaces (`show interfaces terse | match ge-0/0 | no-more` lists ge-0/0/0 to 0/2), and no ready check
  stops at a pager. The probe sends two echo requests per ping and takes one reply, as UDP has two tries.
* The README, the manual (its status, its limits and its SRX section), the guide and the lab's README say ASA output
  was loaded on an ASAv and Junos output on a vSRX, and that the lab policy has no NAT; the limits and the guide had still said only iptables and nftables were
  loaded anywhere.

**Verified, and not**

* The suite (6,637 tests, on Python 3.13 and 3.9; mypy, on both, and pyflakes clean). CI on Windows found one test that
  holds only on POSIX: the mode of `enable_password.txt` (readable by its owner alone; Windows keeps no such bits). It
  is checked on POSIX only.
* The lab, tier 3, the first run of the ASAv (pay as you go, 9.24.10, eu-west-1), by the author: its CLI never
  answered, SSH "Connection refused" for 30 minutes, and nothing told why. The lab now keeps every SSH try (`boot.txt`)
  and saves the firewall's console (`console.txt`, `console.jpg`) before the teardown. The second run's console showed
  the ASAv at its `ciscoasa>` prompt, licensed by AWS, with its own configuration's `ssh 0 0 management` refused while
  the management interface had no address yet: the lab now gives it a Day 0 configuration (management by DHCP, a host
  key, SSH on management, the run's key for `admin`, privileged at login). In the third run the Day 0 configuration
  was taken and SSH answered, but two things kept the lab out: the ASA reads a configuration line of at most 511
  characters, and `ssh authentication publickey` with the run's 4096-bit RSA key was cut off ("Input line size exceeded
  available buffer"), so `admin` had no key; and the ASA offers only an `ssh-rsa` host key, which OpenSSH turns down
  ("no matching host key type found"), for 30 minutes of tries. The ASAv now gets a 2048-bit key (its line about 400
  characters), its ssh runs allow `ssh-rsa` (host key and login, for the ASAv alone), and a try that finds no
  algorithm in common ends the wait at once. In the fourth run ssh took the host key and got in once the ASAv was up,
  but every try then hung for its 120 seconds (12 tries, till the 30 minutes ran out), and the lab had dropped what ssh
  wrote before it hung; it now keeps that in the error and in `boot.txt`. The console showed the Day 0 configuration
  taken without an error this time (the key line fitted) and the ASAv licensed, and no SSH login (it does not log them).
  The fifth run, which kept what ssh wrote, showed the login working and then the ASA's "The enable password is not
  set. Please set it now.": it took the lab's `show version | include up` as the password and `exit` as the repeat,
  and asked again. The Day 0 configuration now sets an enable password made for the run (kept in
  `enable_password.txt`). The sixth run logged in, loaded the policy with no line refused and ran the probes:
  FAIL 7, differs-announced 14, local 32, ok 89, ok-unasserted 18. No flow that should pass got through, also none
  the ASA passes from a higher to a lower security level without a rule; the converted policy reads right (in10 is
  `admin-host`, which `admin-ssh` permits to the DMZ). Its `load.txt` held one letter, "U": the ready check (two
  lines) had worked a second before, but given its hundred lines ahead and the end of its input, the ASA closed the
  session after one letter of its greeting. Nothing was configured, no interface had an address, and with no line
  refused and no success line to look for, the run went on to the probes. The lab now types the ASAv's lines one at a
  time, each once the prompt is back, with the input kept open until the session ends (`Runner.run_paced`); a session
  that answers almost nothing fails, for every firewall; and the ASAv's interfaces, routes, rule hits, drops and two
  `packet-tracer` flows are kept after the probes (`diagnose.txt`). The seventh run, typed line by line, had every
  line answered, and showed the next fault: `interface GigabitEthernet0/0` was "Invalid input" (the marker under the
  name), as were the lines under it, and the `exit` meant to leave the interface left config mode, the next one the
  session. The ASAv on a c5 instance names its data interfaces otherwise; the lab now reads the names from
  `show interface ip brief` (`ports.txt`) and puts them in, in order, for the second to fourth network card. A session
  that ends early now names the refused lines first. The eighth run read `TenGigabitEthernet0/0` to `0/2` and
  configured them, and the ASA took every line but four: `object service tcp-ssh` and `object service tcp-http` were
  "cannot modify system-defined object" (and the `service` line under each "Invalid input"), so `admin-ssh` and
  `outside-web` would have named the ASA's own objects, not the converted ones. A fault of the converter, found by the
  lab: the ASA emitter now keeps object names clear of the ASA's service objects, every `tcp-`, `udp-`, `tcp-udp-`
  and `sctp-` name with one of its port names, and `icmp-` and `icmp6-` with one of its ICMP type names (no list of
  them is published; 9.24 took `udp-dns` and `tcp-high`, whose second word is no port name of the ASA), for objects
  of every kind (one namespace); such an object is renamed (`tcp-ssh_2`, RENAMED). The ASA also warned "Avoid using
  netmask as the end address in range object" for `range 10.20.4.0 255.255.255.255`, the end of the address space,
  which it took. The ninth run, by the author, with these fixes: **PASSED** (local 32, ok 96, ok-unasserted 32), the
  first pass of the ASAv (pay as you go, 9.24.10, c5.xlarge, eu-west-1) and the third firewall of tier 3 to pass, after
  FortiGate and the VM-Series. What it took in the lab, for the next image: a Day 0 configuration (SSH, a host key, the
  key login, an enable password), a key that fits one line of the CLI, `ssh-rsa` allowed, lines typed after each
  prompt, and the interface names read from the device. The README, the manual (its status and its limits) and the
  guide now say so; the limits and the guide had still said only iptables and nftables were loaded anywhere, since
  before the FortiGate and the VM-Series passed.
* The lab, tier 3, the first run of the vSRX (pay as you go, the appsec bundle, 23.4R2-S8.9, c5.xlarge, eu-west-1),
  by the author: SSH and the login worked from the first try after boot, and `show version` answered, but stopped at the
  pager's `---(more)---`, which took the lab's `exit` for a filter ("Match except: xit"); every try hung for its 120
  seconds till the 30 minutes ran out. The vSRX's ready check is now `show version | no-more` (its session already
  starts with `set cli screen-length 0`), and its interfaces, zones, routes, policy hits and configuration are kept
  after the probes (`diagnose.txt`). The second run logged in, loaded the policy, committed it ("commit complete"), and
  nothing passed (FAIL 21, local 32, ok 18, ok-unasserted 89). Its `diagnose.txt` showed why: no `ge-0/0/x` at all in
  `show interfaces terse`, only `fxp0`; the zones named them, by the configuration, and no policy had a hit. The
  management interface had its address 44 seconds before the diagnosis: `show version` had answered within seconds of
  the first login, and the policy was committed and probed in the next 25, before the forwarding engine had made the
  data interfaces. The image ships nothing on them (every `delete` of the session: "statement not found"). The vSRX is
  now ready once `show interfaces terse` lists ge-0/0/0, 0/1 and 0/2. Its `show security policies hit-count` listed
  the deny `guest-not-to-dmz` third, after the two permits, where the configuration has it first; the diagnosis now
  also keeps `show security policies`, with the sequence numbers. The third run, ready once the data interfaces were
  listed: FAIL 1, local 32, ok 38, ok-unasserted 89; 127 of the 128 flows through the vSRX as the source decides,
  among them the guest host's web traffic to the DMZ blocked, so the deny does come first (the hit count's list is not
  the order). The one: `in11>out10:icmp/8`, a ping the policy permits, seen blocked, while every TCP and UDP flow of
  the same host to the same destination passed, and the same ping from in10. The probe sent one echo request, where
  UDP has two tries and TCP the kernel's own; one request lost on the way (the two hosts pinged the same new
  destination at once) read as a block. The probe now sends two and takes one reply. The fourth run, by the author:
  **PASSED** (local 32, ok 39, ok-unasserted 89), the fourth firewall of tier 3 to pass. What it took in the lab: a
  ready check without the pager that waits for the data interfaces, and a second echo request per ping.
* **Not verified**: NAT on any device (the lab policy has none); the Catalyst 8000V of tier 3, and the
  VMs of tier 2, never run.

### 2026-10-17: version 0.36.0

**Results as SARIF, CSV and HTML.** Item 7 of the audit list: the findings of a conversion and of the audit, the zone
matrix, the conduit check and the comparison, for code scanning in a pipeline, for a spreadsheet or a ticketing
system, and as a page someone signs.

**Built**

* `export.py` renders the JSON every result already has: rows per kind (the report's notes and the findings of its
  items, with `--audit` those of the audit before and after the conversion; the audit; the conduit check; the
  differences of a comparison; the cells of the matrix), then SARIF 2.1.0, CSV or HTML.
* SARIF: a rule per code with a link to the manual, levels from the weights, the place of each finding (the rule,
  object, conduit or pair of zones; in the file it is about; the line where its name or uid first stands, from one
  pass over the file), fingerprints of what a finding is about (also as `primaryLocationLineHash`), accepted findings
  as suppressed, what was not checked as run properties, artifacts with their SHA-256, a category per file, a warning
  above GitHub's 25,000 results.
* CSV: a header per kind also without rows, the formula guard (also after spaces and for the full-width signs, now
  shared with `matrix --csv`), line breaks as spaces.
* HTML: one page, nothing fetched, everything escaped: what was read and its SHA-256, counts, findings coloured by
  weight, the accepted apart, what was not checked, the conduits of the model, notes, and a table to sign.
* `--format {text,json,sarif,csv,html}` on `audit`, `conduits` and `compare`, `--format {text,json,csv,html}` on
  `matrix` (`--json` and `--csv` stay); `convert --report-sarif`, `--report-csv`, `--report-html`.

**Review**

*Round 45* by the independent reviewer, of the formats against the SARIF 2.1.0 schema (validated with the schema of
schemastore.org) and GitHub's documentation of code scanning, with injection attempts and large inputs; then a second
pass over the fixes (49 SARIF files valid, injection again, the churn of fingerprints with a line added).

| | Finding | Fix |
|---|---|---|
| high | The audit after the conversion (`EXPOSED_BY_CONVERSION`, a deny no longer enforced) was in none of the three formats | rows for the new, revived and gone findings, with their phase |
| medium | `convert --report-csv` left out the audit | its rows, with a column `section` |
| medium | Paths were written as URIs as they were: spaces, `#`, `%`, drive letters, standard input as a file `-` | percent-encoded references, `file:` URIs for absolute paths, standard input as a description |
| medium | The line of each finding searched the whole file again: hours at the size limit | an index of the file, built once |
| medium | A finding whose name is not in the file was put on line 1 | no line then |
| medium | Fingerprints hashed the message, which holds counts and dates; GitHub matches by `primaryLocationLineHash` | what a finding is about, written as both |
| medium | One category for every file: two firewalls uploaded apart closed each other's alerts | `fwshift/KIND/FILE/` |
| medium | What was not checked (inside zones not checked, rules not read, not followed, ...) reached no format | an HTML section and SARIF run properties; the compare's inside-the-zone flag as a column |
| medium | The version was not bumped | 0.36.0 |
| low-medium | No word above GitHub's 25,000 results per run | a warning on standard error |
| low | The same file twice made two equal artifacts, which the schema forbids | one artifact per file |
| low | An empty CSV had no header; whitespace in names was collapsed | the header always; values as they are |
| low | `matrix --csv` did not guard a formula after spaces; full-width signs were not guarded | one guard for both |
| low | A model from standard input lost its SHA-256 (read twice) | read once |
| low | A closed conduit was reported as a rule, in the policy | a conduit, in the model |
| low | Names escaped in XML or JSON were not found for their line; a uid was not used | unescaped forms, ids first |
| low | Accepted findings stood among the open ones in the HTML; source ids were left out | a table of their own; a column |
| low | Docs: synopses without `--format`, the fingerprint promise | rewritten |
| medium (second pass) | A number among the source ids (a FortiOS policy id) was looked up as a word, and found anywhere in the file | only uids and paths; the line IOS, Huawei and Stormshield keep, as it is |
| medium (second pass) | Ids that say where a rule stands (a line, a priority, a position) were in the fingerprint: a line added above changed it | left out |
| low (second pass) | An audit alone and in a conversion had other fingerprints in one category | the same |
| low (second pass) | The category depended on the slashes and lost characters; absolute URIs were not normalised | relative to the working directory, percent-encoded; normalised |
| low (second pass) | CSV columns came and went with the findings; `matrix --csv` ended lines with LF | the same columns; CR LF |
| low (second pass) | A comparison's renamed second zones, an audit's proposals and summaries, the SL-T and direction of a conduit were left out | columns and counts |

Not done: no byte order mark in CSV (documented: open it as UTF-8); no `--sarif-category` (the category is the file);
the cells of the matrix in HTML list their rules by name (their sources, destinations and services are in `--csv`).

**Verified, and not**

* The suite (6,623 tests, on Python 3.13 and 3.9; mypy and pyflakes clean). `tests/test_export.py` checks the SARIF files of the samples against the parts of SARIF 2.1.0 FWShift
  writes (versions, rules and their indexes, levels, locations and artifacts, fingerprints, suppressions, unique
  artifacts, the category), the CSV against its header and the formula guard, the HTML against injection through every
  field, and each review finding above.
* The lab, tier 2, run by the author on his own Debian with 0.36.0: `nftables` and `iptables` passed, 128 flows through
  the firewall as the source decides and 32 local flows not asserted, as with 0.32.1: the change to traffic inside a
  zone (0.33.0) broke neither. The lab policy has no interfaces or routes, so the networks of 0.35.0 were not used.
* **Not verified**: an upload to GitHub code scanning, GitLab or Azure DevOps; the page printed on paper; Excel's
  handling of the guarded cells beyond what is documented of it.

### 2026-10-17: version 0.35.0

**The networks behind the zones, from the source.** Item 1 of the audit list: where a FortiOS, PAN-OS or ASA
configuration holds its interfaces and static routes, FWShift reads where each address lies, and the targets that need
the networks of the zones, and the equivalence check, take them from there where `--zone-network` does not give them.

**Built**

* `zonenets.place`: each network (of an interface, a static route, an address pool) in the zone of the interface it is
  on or that its route leaves by; a route that names only its next hop by the route to that address, the longest prefix
  first, in its own routing table, recursively. Of routes to one network the connected one wins, then distance, then
  metric; routes alike by different zones place it behind no zone (`ZONE_NETWORKS_CONFLICT`). A range is the networks
  it is made of.
* **Behind no zone** (`Policy.unzoned_networks`, `Options.zone_excluded`): the networks of an interface in no zone of
  the policy (management, another virtual system or VDOM, a VPN no rule names), of one that is down, routes that drop or
  lead to another router, conflicts, next hops that lead nowhere known. `zone_spaces` takes them like a zone in "the
  smaller decides" and gives them to no zone, so that the zone of the default route does not take them: an allow for it
  leaves them out, a deny keeps them. Allow rules for any zone and any address are written for `FWSHIFT-ROUTED`, every
  address but these (`ZONE_NETWORKS_ANY_ZONE`).
* With routing protocols, or zones whose interfaces are not layer 3 (virtual wire, layer 2, tap, virtual-wire pairs,
  bridge groups), not every network is known: the default route is then not taken as "everything else"
  (`ZONE_NETWORKS_PARTIAL`).
* The parsers: FortiOS (interfaces of the VDOM with secondary and extra IPv6 addresses, status down, zones, static
  routes by interface, SD-WAN zone or to an address object, blackholes, routes to internet services placing nothing,
  SSL VPN and mode-config pools, phase 2 remote networks), PAN-OS (layer-3 interfaces, units, VLAN, loopback, tunnel,
  literal or object addresses, virtual and logical routers of the virtual system, discard, next router, no-install,
  GlobalProtect pools), ASA (interfaces, shut down, management-only, `route`, `ipv6 route`, Null0, `tunneled`, the
  shorthand `0 0`). The set reader of 0.34 learned logical routers, VRFs, IPv6 interface addresses and static routes
  in one command.
* `zonenets.for_target`: the networks for a target, by the names after `--zone-map`, under `--zone-network` (what is
  given decides; what the source puts in a zone that is given other networks, and they do not hold, is behind no zone);
  `--no-source-networks` on `convert` and `compare`. `ZONE_NETWORKS_ONE_VERSION` where the policy has addresses of an IP
  version that no zone's networks have.
* ASA and pfSense targets: a rule that names its destination, for some zones, now leaves out the part of the destination
  that lies in none of the networks when it allows (it kept it, with a note): the reviewer's side finding, which the
  networks behind no zone made matter.
* `convert --compare` to an ASA target compares where the source tells the networks; the FortiOS sample got a default
  route; the goldens of the ASA and FortiOS samples changed accordingly (rules that were written disabled for want of
  networks are written).

**Review**

*Round 44* by the independent reviewer, of the feature, with synthetic configurations written to find where the
networks make a converted policy allow more than the source, and a fuzz; then a second pass over the fixes.

| | Finding | Fix |
|---|---|---|
| high | The networks of interfaces in no zone (management), and of routes that drop, conflicts and other routers, fell into the zone of the default route: an allow for it reached them (rules 0.34 wrote disabled) | behind no zone, carved out of every zone (`zone_spaces`) |
| high | With routing protocols the default route still made "everything else" one zone's, learned networks with it | not taken; `ZONE_NETWORKS_PARTIAL` |
| high | FortiOS secondary addresses were not read: they fell into the default zone | read |
| high | The suite was red (goldens, a stale test, the version) | fixed |
| high (second pass) | An ASA `tunneled` default route made inside the zone of 0/0 (SSH from almost everywhere on NSX) | not read |
| high (second pass) | A FortiOS route to an internet service, which has no `dst`, was read as a default route | not read |
| medium | Next hops were resolved across virtual routers and virtual systems; a next hop behind a static route was lost | in its own table, recursively, by longest prefix; checked by an independent routing oracle |
| medium | A zone given with `--zone-network` dropped the rest of its source networks into the default zone | behind no zone |
| medium | VPN pools fell into the default zone | FortiOS SSL VPN, mode-config and phase 2, PAN-OS GlobalProtect, behind their tunnel |
| medium | Routing protocols of logical routers were not seen | seen |
| medium (second pass) | An allow for any zone and any address was written as ANY, reaching the networks behind no zone | `FWSHIFT-ROUTED` |
| medium (second pass) | A pool range across two networks aborted the conversion with an error about `--zone-network` | taken as its networks |
| medium (second pass) | Dial-up IPsec remote networks fell into the default zone | behind the tunnel |
| low-medium (second pass) | Another virtual system's routers took part, making the own networks conflicted | only the routers of the virtual system |
| low-medium (second pass) | The addresses behind virtual-wire, layer-2 and tap zones went to the default zone | no default then (`ZONE_NETWORKS_PARTIAL`) |
| low | Routes through a shut-down ASA interface were placed; FortiOS `status down` ignored; `route outside 0 0` not read | behind no zone; read |
| low | PAN-OS no-install and multicast routes placed; a next hop as an address object lost | skipped; resolved |
| low | `ZONE_NETWORKS_ONE_VERSION` on policies without the other version; FortiOS full configurations looked like dynamic routing | only where the policy has such addresses; real protocol settings only |
| low | Docs: management networks "not taken" without saying where they went; `--compare` shares the networks | rewritten; §17 says so |

Kept as it is: `ZONE_NETWORKS_FROM_SOURCE` stays a note (information), not a review item, also where a default route
is taken; what the networks are is in it and in `ZONE_NETWORKS`.

**Verified, and not**

* The suite (6,603 tests, on Python 3.13 and 3.9; mypy and pyflakes clean). `tests/test_zonenets.py`: an independent longest-prefix routing judge against `zone_spaces(place(...))`
  for random routing tables (interfaces in zones and in none, routes by interface and by next hop, floating and
  equal-cost routes, routes that drop, pools; 150 in the suite, 3,000 more run once), the three parsers on synthetic
  configurations of each case above, and a differential: the output with the networks of the source is the output with
  them given, for nine targets and two samples.
* **Not verified**: on a device, and against configurations of real networks (there are none in the project). PAN-OS
  templates of Panorama, and the other sources that hold interfaces (Junos, Huawei, IOS, Sophos, pfSense, OPNsense,
  RouterOS, SonicWall), give no networks yet. The equivalence check judges the output with the networks it was written
  with: a network the routes put behind the wrong zone is found by reading `ZONE_NETWORKS`, not by the comparison.

### 2026-10-17: version 0.34.0

**PAN-OS in set format, read.** What a firewall or Panorama prints with `set cli config-output-format set` and
`show config running`, and what FWShift's own PAN-OS target writes (item 3 of the conversion list, and the PAN-OS
part of item 3 of the audit list: `convert --to panos --compare` reads the output back now).

**Built**

* `parsers/panos_set.py`: a set command stands for the XML its words name, and is read as that XML, which the PAN-OS
  parser reads as before; the only thing it learned is to tell XML (also UTF-16 or UTF-32 with a byte order mark) from
  commands. What is an entry, a list of members or a value is PAN-OS's schema, as far as the parser reads it: the
  objects of a virtual system are entries only where objects stand (`schedule` in a rule is a value), the words of a
  rule that are lists, the interfaces of a zone and of a virtual router, a NAT rule's one service. Where a command
  begins: `shared`, `vsys NAME`, `device-group NAME`, the objects and rules of a virtual system without one of them in
  `vsys1` (made only when one comes), and the rest (`deviceconfig`, `network`, a template of Panorama, a log collector)
  in the device, where it hides no device group.
* Commands as the CLI takes them: several values in one command, also after a part of a rule the parser reads
  (`profile-setting`, `qos`, `target`, `option`, the translations of NAT); a list of entries at once
  (`vsys [ vsys1 vsys2 ]`).
* Values as PAN-OS prints them: in double quotes, over several lines (certificates, banners), a backslash as it is
  (`"EXAMPLE\domain users"`), a quote inside a value as it is. A quote ends a value where what follows reads as words
  of a command, or at the end of a line that a command follows; free text as the last value of a line runs to its
  end; a value that ran over a line ends only at the end of one; one that runs into the commands after it is refused.
* What a session prints around the commands (the prompt, `configure`, `[edit]`, `show`, `set cli ...`) is left out;
  other commands (`delete`, `rename`) and a relative `[edit LEVEL]` are said (`SET_COMMANDS_NOT_READ`), and how many
  commands were read (`PANOS_SET_FORMAT`).
* Detection: PAN-OS set commands before Junos (their first words do not overlap), not where the file has FortiOS's
  `config`, `next` and `end` lines.
* The PAN-OS target writes a backslash as it is, as PAN-OS prints it, where it wrote `\\`; a double quote inside a
  value as a single one, and a line break as a space (descriptions; the goldens of ASA, Management Center and FortiOS to
  PAN-OS changed by these characters only). Output of 0.33 and earlier, read back, has two backslashes there.

**Review**

*Round 43* by the independent reviewer, of the reader, against what it knows of PAN-OS 9 to 11 and what Palo Alto's
community shows of the format, with probe scripts and a fuzz of 30,000 cases; then a second pass over the fixes.

| | Finding | Fix |
|---|---|---|
| high | `schedule` in a rule was read as an entry: the rule came back without its schedule, a time-limited allow made permanent | objects are entries only where objects stand |
| high | Any command that was not of the device went to `vsys1`, which made one up: a Panorama dump with a template, a log collector or `set cli` read as `vsys1` with no rules, and no word | first words of a virtual system go to `vsys1`, the rest to the device; `set cli` left out; `set device-group X` alone makes it |
| high | A quoted value over several lines (a certificate, a banner) refused the whole file | commands are read from the text, not per line |
| high | A backslash in a quoted value was taken as an escape; PAN-OS prints it as it is (`"pancademo\server operators"`) | taken as it is; the target writes it so too |
| high (second pass) | A banner over several lines that quotes a word ended at that word, and its last quote swallowed the commands after it | a value that ran over a line ends only at the end of one that a command follows; one that runs into commands is refused |
| medium | A UTF-16 XML export, which 0.33 read, was taken for set commands | byte order marks recognised, for both |
| medium | An entry word followed by a list (`target devices X vsys [ vsys1 vsys2 ]`) refused the file | an entry per value |
| medium | Several values in one command lost all but the first ones (`disabled yes description old` came back enabled); after a part of a rule, the words that followed went into it, and a NAT `service` was taken for a part | value words take their value and the command goes on; back out of a part that does not hold the word; NAT `service`, `translated-address`, the interface address as values |
| low | A copied session gave a review note of `configure`, `show`, `[edit]` | left out |
| low | Quoted `"]"` was taken for the end of a list; unquoted `description [legacy]` was lost | words know whether they were quoted; text in brackets is text |
| low | A path of a thousand words crashed in the XML writer | refused beyond 64 elements |
| low | A flat FortiOS fragment of another section than `firewall`, `system`, `vpn`, `router` or `user` was taken for PAN-OS | FortiOS is any `config` line with `next` or `end` lines |
| low | `qos marking follow-c2s-flow` and `override no` lost their value element | written as elements |
| low | A NAT `service [ x ]` silently matched any service | one value taken, several refused |
| low | `pre-rulebase` without a virtual system went to the device | to `vsys1` |
| low | Two quoted phrases in a description ended it at the first | free text as the last value of a line runs to its end |
| low | The target's dynamic filter still escaped `\` and `"` | as every value |
| low (tests) | The differential test copied the reader's escaping, and had no schedule, Panorama hierarchy, template, targets, NAT forms, zones other than layer 3, multi-line values | `quoted` prints as PAN-OS does; a synthetic firewall and Panorama in the test file |

**Verified, and not**

* The suite (6,416 tests, on Python 3.13 and 3.9; mypy and pyflakes clean). The differential test prints XML as PAN-OS prints set commands (an entry as the word of its list and its
  name, a list of members in brackets or as one word, a value after its path, an element without one as a last word),
  with literal quoting, and checks that the samples, a synthetic firewall with the rest of what the parser reads and a
  synthetic Panorama (device groups in a hierarchy, a template, targets) read to the same model and the same notes as
  their XML. Random policies through the PAN-OS target read back to the same rules, and write the same commands again;
  `convert --compare` to PAN-OS finds them equivalent. Fuzzing (65,000 cases from both review passes) raised nothing
  but FWShift's own errors.
* **Not verified**: on a device. No real output of `show config running` in set format was available; the format is
  from Palo Alto's documentation and community posts, and from the target's own output, which loaded on a VM-Series
  (0.32.1). Whether Panorama prints `set readonly ...` lines (the hierarchy of device groups) is not confirmed, and how
  PAN-OS prints a double quote inside a value, and whether its CLI takes one, is not known: the target writes none.

### 2026-10-17: version 0.33.0

**What no rule matches inside a zone, across the targets.** The two open items of the conversion list (19 and 20), and
what the review of them found.

**Built**

* `transform.zone_members`: which source zones and interfaces `--zone-map` makes a target zone of. Only names the
  source knows count (its zones, and those its rules name): a map entry for a name it does not know, a typo, merges
  nothing. `merged_zones` and `intrazone_decisions` use it; `merged_zones` counted every map entry.
* The zone's own setting either way. The model says it with `Zone.intrazone_allow` (None: the policy's default), and
  several emitters read only `True` from it: where the default allows inside a zone, they let through inside a zone
  that blocks (no parser gives that combination yet: PAN-OS has no setting per zone, FortiOS and SonicWall block by
  default). Now the decision of `intrazone_decisions` is what they write:
  * PAN-OS: where the source allows inside a zone, as PAN-OS does, an intrazone deny at the end for the zones that
    block (their own setting, or zones the map merges); written also for a policy without security rules, and for the
    zones NAT rules name.
  * Check Point, SonicWall, Huawei, IOS, Stormshield, RouterOS, Forcepoint: the decision per zone, with merges and
    renames; their zone lists take the names after the map (some kept the names before it).
  * iptables, nftables, pfSense, OPNsense, NSX, and Junos with `default-policy permit-all`: their default, written for
    traffic between zones, lets through inside a zone that blocks; said (`INTRAZONE_DENY_NOT_WRITTEN`).
* SonicWall: a zone no rule names, whose name SonicOS does not take, is left out and said (`ZONE_NAME_INVALID`).

**Review**

*Round 42* by the independent reviewer, of the change, with probe scripts, read-back comparisons and a differential of
Check Point.

| | Finding | Fix |
|---|---|---|
| high | Huawei, IOS, Stormshield and RouterOS (not touched by the change) passed traffic inside a zone `--zone-map` merges, which is traffic between zones the source keeps apart; read back and compared, RouterOS and Huawei opened them | `intrazone_decisions` and the zone names after the map in all four |
| medium | PAN-OS wrote no intrazone deny for a source without security rules (an early return) | the tail is written whatever the rules |
| medium | PAN-OS left out zones only NAT rules name, merged zones among them; `note_closed_zones` too | the zones of the NAT rules as well |
| medium | A renamed zone that blocks: Forcepoint, Huawei, Stormshield and RouterOS blocked under the old name (latent) | the decision under the new name |
| low | `INTRAZONE_DENY_NOT_WRITTEN` on ASA overstated (an ASA does not send traffic back out of its interface without `same-security-traffic`) | not raised for ASA |
| low | SonicWall wrote zone names it refuses for a zone no rule names | left out, said |
| low | The note on a merge said nothing was written where PAN-OS writes a deny | worded for both |

A second pass over the fixes (read-back comparisons with the prefixes aligned, zones only NAT rules name under six
zone maps, 80 seeds of the Check Point differential with merges) found nothing that allows more, and two leftovers,
fixed: Forcepoint still listed the zone names before the map (a rule for an old name no rule uses), and a renamed or
merged zone lost the interfaces of its source zones in the hints of Huawei, IOS and RouterOS
(`transform.target_interfaces` gives them now).

**Verified, and not**

* The suite (6,340 tests, on Python 3.13 and 3.9; mypy and pyflakes clean). The pfSense test of a source's defaults
  now expects `INTRAZONE_DENY_NOT_WRITTEN` as well (its model blocks inside a zone and allows between zones). The Check Point differential now has sources that allow inside a zone with one zone that
  blocks, and its judge reads the zone's own setting either way; `tests/test_intrazone.py` covers PAN-OS, SonicWall,
  the five targets that decide inside a zone themselves with a merge, the notes, a typo in the map, and a source without
  rules. Planted faults (the map's keys counted again; the Check Point and four emitters of 0.32.1) fail them.
* **Not verified**: on a device. `note_closed_zones` sees merges of the zones the source defines, not of names only its
  rules use (latent: no parser gives a zone that blocks while the default between zones allows).

### 2026-10-16: version 0.32.1

**The first real runs of the lab**, made by the author on his own machine and accounts, and what they found: one
difference in the Google Cloud converter, and what the lab got wrong (the key Azure takes, the routing of a host's own
subnet on Google Cloud).

**The runs** (the lab policy, `lab/policy/lab_panos.xml`, converted by 0.32.0 and the fixes below as they came)

| Run | Target, where | Result | Torn down |
|---|---|---|---|
| tier 2 nftables | the author's Debian (network namespaces) | ok 128, local 32: PASSED | yes |
| tier 2 iptables | the same | ok 128, local 32: PASSED | yes |
| tier 1 AWS | eu-west-1 | ok 144, ok-unasserted 16: PASSED | yes: no instance, no VPC left |
| tier 1 Azure, first try | West Europe | refused: the run's Ed25519 key (Azure takes RSA only for its VMs); nothing was made | yes |
| tier 1 Azure, second try | West Europe | refused by Azure: "the selected region is currently not accepting new customers"; North Europe does not offer `Standard_B1s` to the subscription | yes |
| tier 1 Azure | Germany West Central | ok 144, ok-unasserted 16: PASSED | yes |
| tier 1 Google Cloud | (the author's project) | ok 128, differs-announced 32: PASSED | yes: no instance, network or policy left |
| tier 1 Google Cloud, with the converter of 0.32.1 | the same | ok 128, FAIL 32: the flows inside a zone still blocked | yes |
| tier 1 Google Cloud, 0.32.1 with the own subnet through the gateway | the same | ok 160: PASSED | yes |
| tier 3 FortiGate-VM, PAYG (`FortiGate-VM64-AWSONDEMAND build0245 (8.0.1) GA`), c5.xlarge | eu-west-1 | ok 128, local 32: PASSED; every line of the policy accepted | yes |
| tier 3 VM-Series, first try | eu-west-1 | the BYOL image found (see below); AWS refused it, `OptInRequired`; no firewall ran | yes |
| tier 3 VM-Series PAYG Bundle 1 (`PA-VM-AWS-11.2.15`), m5.xlarge | eu-west-1 | every line of the converted policy accepted and committed; one line of the lab's own clean-up refused, which stopped the run before the probes | yes |
| tier 3 VM-Series, the clean-up in its own session | eu-west-1 | both sessions through, the policy committed; then test host in11 never passed its self-check (15 minutes), so no probe was sent | yes |
| tier 3 VM-Series PAYG Bundle 1 (PAN-OS 11.2.15), with the host diagnostics and the address fallback | eu-west-1 | ok 128, local 32: PASSED | yes |

* The 16 unasserted flows of AWS and Azure are those from inside to outside (in10 and in11 to out10): the rule
  `inside-out` allows every service, and part of that (protocols other than those a security group or a security rule
  names) cannot be written, which the report says. All 16 came through as the source decides.
* The 32 of Google Cloud are the flows inside a zone (in10 and in11, dmz10 and dmz11): PAN-OS allows them when no rule
  matches, and the converted policy blocked them. The report said so (`INTRAZONE_DEFAULT`), so the lab did not assert
  them and the run passed; the converter fixed below writes them.
* The second Google Cloud run, with the rules inside a zone written and asserted, still saw those 32 blocked: not the
  policy (its rules allow them, and it ends after them), but the lab's routing. The first-boot script sent a host's own
  subnet out on the link, and a Google Cloud instance has a `/32` and reaches even its neighbours through the gateway,
  whose network answers ARP for the gateway only ([Compute instance netmasks](https://docs.cloud.google.com/vpc/docs/compute-instance-netmasks)).
  The first run hid it: the policy blocked those flows as well. On Google Cloud the script now routes the own subnet
  through the gateway; AWS and Azure, which answer ARP for every address and passed, keep the route on the link. The
  next run passed with all 160 flows as the source decides.
* The FortiGate run is the first time a conversion was loaded on a vendor's firewall: the FortiOS configuration
  written from the PAN-OS policy (addresses, services, seven policies in the source's order, the deny first) was typed
  into the CLI of FortiOS 8.0.1 over SSH, which added every entry and refused none, and the 128 connections through
  it came out as PAN-OS decides. The lab's steps for a FortiGate (the image found by name, the login with the run's
  key, the interfaces from the user data, the ready check) all worked the first time. The run did not keep which
  version the image had: a tier-3 run now writes the image's name and product code into `run.json` and the answer of
  the ready check (the version, on a FortiGate) into `ready.txt`.
* The first VM-Series run found the BYOL image (`PA-VM-AWS-11.1.6-h39`, product code `6njl1pau431dv1qxipg63mvah`): BYOL
  and the two pay-as-you-go bundles share their name, and the lab looked by name only. It now looks for the product code
  of PAYG Bundle 1 as well (Palo Alto lists the three codes); Bundle 2 is given with `--ami`.
* The VM-Series run with Bundle 1: PAN-OS 11.2.15 took every line of the converted policy and committed it. What it
  refused was the lab's clean-up of the example older images ship with (rule1, the virtual wire `default-vwire`, zones
  trust and untrust): 11.2 has none of it, and answers a delete of what is not there with an error ("No object to
  delete", "Object doesn't exist", and for the virtual wire "Invalid syntax."). The clean-up is now a session of its
  own, committed, whose answers do not count (`prepare.txt`); the session that is checked has no delete.
* The next VM-Series run loaded and committed the policy, and then one test host (in11) never passed its self-check:
  the firewall plays no part in that check (the host asks its own address over the loopback). The lab could not say why,
  as the teardown took the host. A host that fails its self-check is now asked about itself first (its addresses, the
  routing of its test address, what listens, the probe's service, the end of its first boot) into
  `diagnose-HOST.txt`, which the error names. And the first-boot script no longer depends on DHCP alone for the test
  address of an interface attached after boot: after two minutes without it, it puts the address on the interface that
  has none. The run after that passed: PAN-OS 11.2.15 decided the 128 connections through it as the source does. (The
  lab policy is itself PAN-OS: this run checks the `set` commands FWShift writes, the policy read into the model and
  written out again, on a real PAN-OS.)
* Before the runs, the Windows job of the CI failed two probe tests: Windows reports a closed TCP port only after
  about two seconds, a closed UDP port as `ConnectionResetError`, and its ping takes other options. The probe speaks
  each system's ping and takes their error numbers from `errno`; the test waits longer on Windows.

**Built**

* Google Cloud converter: what no rule matches inside a zone, where the source decides it otherwise than between zones
  (PAN-OS allows it; a FortiOS zone with `set intrazone allow`), is written as rules for the networks of each such
  zone to themselves, after the rules of the source and before its default (`fwshift-intrazone-ZONE`,
  `INTRAZONE_WRITTEN`). A zone without networks is said, in the direction it errs: an allow that is blocked
  (`INTRAZONE_DEFAULT`), a block that is let through (`INTRAZONE_DENY_NOT_WRITTEN`). The AWS and Azure converters
  already wrote it; their runs showed no difference.
* `transform.intrazone_decisions`, which the three cloud converters now share: a zone's own setting looked up under
  its name before `--zone-map`, and a zone the map makes of several gets an allow only where the source allows
  between zones too (`INTRAZONE_ALLOW_MERGED`), a block also between them (`INTRAZONE_DENY_MERGED`). The zones of the
  target are named after the map, never `any`.
* The lab: an RSA key (4096 bits) for Azure and for the images of tier 3; the Azure module refuses another kind. The
  stand-in public keys of a dry run (where ssh-keygen does not run) are well formed and spell out that they are no key;
  the RSA one was not even valid base64. The
  lab README says what stops a new Azure subscription (multi-factor sign-in to the tenant, regions that refuse new
  subscriptions, the quota), how Google Cloud and AWS are logged in, and what the runs verified.
* The status of the README, the manual and this file: AWS, Azure and Google Cloud verified by the lab.

**Review**

*Round 41* by the independent reviewer, of the Google Cloud change, with probe scripts and differential tests.

| | Finding | Fix |
|---|---|---|
| high | Zones merged by `--zone-map` (inside and dmz into one) got an allow inside the merged zone, which opened traffic between them that the source blocks; Azure did the same (older code) | `intrazone_decisions`: no allow for a merged zone unless the source allows between zones; AWS, Azure and Google Cloud |
| medium | A zone renamed by `--zone-map` lost its own setting (FortiOS `set intrazone allow`), and the note named the old zone | the setting looked up under the source name; the zones of the target named after the map |
| medium | `INTRAZONE_DEFAULT` covered a block inside a zone that the converted policy lets through, and the tests counted it as allowing less | its own code, `INTRAZONE_DENY_NOT_WRITTEN`; a test that accepts more only there |
| low | A zone named `any` in `--zone-network` got rules inside it | `any` is no zone of the target, and `--zone-network` refuses it as `--zone-map` does |
| low | The overlap subtraction did nothing (`zone_spaces` gives each address to one zone), and the manual said otherwise | removed; the manual says the smaller network decides |
| low | A blocking rule that is not written now meets the allow inside its zone, not the final deny | said in the manual; its finding already warns |

A second pass by the reviewer over the fixes (a new differential probe on the three clouds: random defaults, zones
without networks, merges, a zone holding `0.0.0.0/0`, `--inside-zone`, a zone only `--zone-network` names) found
nothing that allows more without a note naming it, and one more low finding, fixed: a `--zone-map` entry for a zone
the source does not know (a typo) counted as a merge. (The older `merged_zones` of the PAN-OS and Check Point
emitters still does; on the list.)

Also found while adding tests: with the default between zones allow and a zone that blocks inside itself, the AWS
converter wrote "allow everything" and let that zone's traffic through; it now leaves out the zones that block, and
needs the networks of those zones only.

**Verified, and not**

* The suite (6321 tests, on Python 3.13 and 3.9; mypy and pyflakes clean), with new differential tests: for Google Cloud, AWS and Azure, random policies with random
  defaults inside and between zones and zones with their own setting, every packet as the source decides; for Google
  Cloud also zones without networks and zones merged by `--zone-map`. The planted faults (no rules inside a zone, the
  merge ignored, the AWS default as before) each fail them.
* The lab on Google Cloud with 0.32.1: all 160 flows asserted and all as the source decides, the 32 inside a zone
  among them. **Not verified**: AWS and Azure again with 0.32.1 (their converters' change only touches `--zone-map`
  and a zone that blocks inside itself, which the lab policy has neither of); a real run of the zone map on any cloud;
  the VMs of tier 2, the other images of tier 3 (vSRX, Catalyst 8000V, ASAv), and the workflow in GitHub.

### 2026-10-15: version 0.32.0

**The lab**: scripts that put a converted policy on real targets and check it with real connections (`lab/`, its
`README.md`).

**Built**

* `lab/lab.py` and its modules: one synthetic policy (`lab/policy/lab_panos.xml`, three zones, a deny above the
  allows, a deny inside a broad allow, ports, a range, UDP, ICMP), converted for the target; a plan of 160 flows
  between five test hosts with what the source decides (FWShift's first-match simulation), asserted only where every
  rule that might match was converted exactly and no note on the target's defaults applies; the 32 flows inside a
  zone shown as `local` where they do not pass the firewall (tiers 2 and 3); a probe in plain Python on each host,
  which checks itself first; the check and its summary, which does not pass a run that saw only one kind of verdict;
  `--dry-run`, which converts and plans for real and only writes down the rest.
* The teardown: after a failure, Ctrl-C, SIGTERM or SIGHUP, with the running command interrupted once and the
  teardown shielded; `run.json` in the work folder, from which `destroy` and `destroy-all` tear down a run that was
  kept or killed; what is left after a teardown listed by the run's id.
* Tier 1, the cloud-native targets: Terraform for AWS, Azure and Google Cloud (a management interface that accepts
  only the admin address and sends nothing out, and a test interface per host), and the loading of each conversion
  (the security groups attached by their `# attach` lines and tagged with the run, the NSGs associated by the networks
  in the template, the network firewall policy associated with the test network).
* Tier 2, a local Linux host: nftables and iptables in a network namespace (no image), and RouterOS CHR, OPNsense and
  pfSense under QEMU/KVM from a base image prepared once (the RouterOS script imported and switched on and its rules
  counted; the pfSense and OPNsense areas put into `config.xml` as a restore does, the filter reloaded and checked
  with `pfctl -sr`). The bridges and QEMU are in a namespace of their own: the host's network and settings are not
  touched.
* Tier 3, AWS Marketplace images: one Terraform module for a firewall with an interface per zone and a route table
  per zone subnet, and for FortiGate, VM-Series, vSRX, Catalyst 8000V and ASAv the base configuration and the
  conversion typed into the CLI over SSH, with every refused line, and a missing commit success line, a failure. The
  images it does not script are listed with the reason.
* `.github/workflows/lab.yml`: on a change to `lab/`, the Terraform modules validated and every run made dry; by hand,
  a real run of tier 1 or 3 in the environment `lab`, logged in with OpenID Connect (no stored keys), its inputs
  checked, a teardown of what is left that always runs, the work folder kept with the Terraform state and without the
  run's private key.
* `tests/test_lab.py`: the plan against the test suite's own judge, the probe on loopback (its errors and its
  self-check too), the reading of each conversion, every run dry, a kept run destroyed later, and real runs through
  the kernel (nftables and iptables) with a ruleset that lets everything through as the control that must fail, and a
  SIGTERM in the middle of a run.

**Review**

*Round 40* by the independent reviewer, of the whole lab, with a real run of the kernel tier.

| | Finding | Fix |
|---|---|---|
| high | Ctrl-C reached Terraform twice (the process group), which then quit without writing its state | each command in a session of its own; the run passes the interrupt on once and waits |
| high | A cancelled workflow (SIGTERM) or a closed terminal (SIGHUP) skipped the teardown | both handled as Ctrl-C, the teardown shielded; `destroy`, `destroy-all`; a cleanup step in the workflow that always runs |
| high | The workflow's AWS credentials (1 hour) ran out before a tier-3 run and its teardown | 3 hours asked for; the README says to allow the role that much |
| high | AWS: the converted security groups were neither tagged nor sure to go (a group still attached cannot be deleted) | tagged with the run; interfaces moved back to the holding group first; a second try; leftovers listed |
| high | Google Cloud: the policy's association was deleted only when the run got that far | deleted whenever the policy was made |
| medium | Workflow inputs went into the shell unchecked; `--admin-cidr` took any network | checked against patterns and passed as an array; one address unless `--allow-wide-admin` |
| medium | The test hosts' management interfaces could send anywhere | egress denied on each cloud |
| medium | Tier 3: the VPC delivers by destination, so the hosts' next hop to the firewall was ignored | a route table per zone subnet to the firewall's interface |
| medium | Tier 3: the Elastic IP could be made before the internet gateway; provider versions open-ended; images of any architecture | `depends_on`; versions bounded; x86_64 only, the image's name and product code printed |
| medium | Tier 3: the CLI was taken as ready on its first answer; the default zones and rules of VM-Series and vSRX stayed | a ready answer per image; the defaults deleted first |
| medium | Plan: the report's notes on the target's defaults were ignored | flows they touch not asserted |
| medium | Probe: a source address it could not bind read as `blocked` | `error`; a self-check before the flows |
| medium | Flows inside a zone, which never pass the firewall in tiers 2 and 3, were asserted | `local` |
| medium | `plan` ignored the tier; a dry run printed `PASSED`; a failure to make the run exited 1 like a failed check | the plan per tier; `DRY RUN`; exit 2 |
| medium | Tier 3: `end` in the IOS and ASA conversions closed the session before the base configuration was saved | dropped from the conversion |
| medium | Tier 3: sessions had no time limit and no proof of a commit | 20 minutes; the commit's success line required |
| medium | RouterOS: an import that stopped half way passed | the script's last line required, its rules counted |
| medium | pfSense/OPNsense: a reload that loaded nothing passed | `pfctl -sr` must name the lab's addresses |
| medium | Tier 2 turned a setting of the host off (bridge netfilter) and put bridges in its network | the bridges and QEMU in a namespace of their own; nothing of the host changed |

**What the work made necessary**

* *Zone networks under the mapped names.* The OPNsense and pfSense runs gave `--zone-network` the zones' names
  before `--zone-map`; FWShift read them as further interfaces, every allow became approximated, and no asserted flow
  was expected to pass. The new check against vacuous runs caught it in the dry runs: the networks now take the
  mapped names, and 96 flows are asserted.

**Verified, and not**

* The suite (6156 tests, on Python 3.13 and 3.9; mypy and pyflakes clean), with the real runs of nftables and iptables: 128 flows each through the kernel, all as the
  source decides (21 passed, 107 blocked or refused), 32 local, the host's settings unchanged and no namespace left;
  the wrong ruleset failing more than 50 asserted flows; a SIGTERM in the middle of a run tearing it down.
* **Not verified**: no run of tier 1, of the virtual machines of tier 2 or of tier 3 was made; the Terraform modules
  were neither applied nor validated here (the workflow validates them on GitHub). The Marketplace image names, the
  logins and first boot of the firewalls, the reload commands of OPNsense and pfSense and the routing of the test
  hosts' second interface on each cloud are taken from documentation.

### 2026-10-15: version 0.31.1

FWShift is on PyPI (`pip install fwshift`), uploaded by the release workflow of 0.31.0. This version puts the
project's page there in order; nothing in the converter changed.

**Built**

* The release workflow uploads the wheel and the source distribution to PyPI by trusted publishing: a job of its own
  after the release job, in the environment `pypi` (which waits for a reviewer), for a pushed tag only (PyPI never
  takes a version twice). The actions it uses are pinned to the commits of their releases, as the others are.
* `pyproject.toml`: a description of what FWShift is now (it named twelve platforms), the links PyPI shows
  (repository, manual, development log, issues), the Python versions and topics.
* The README is the page on PyPI, where relative links lead nowhere: its links are to the repository. The manual,
  the README and the guide install with `pip install fwshift`.
* Forms for issues: one for a problem, one for what a device did with the output. Both say not to paste a
  configuration from a real network, and the first makes the reporter confirm it.
* A test that the README has no relative links, and that the links PyPI shows are there.

**Verified, and not**

* The suite, mypy and pyflakes as for 0.31.0; the wheel and the source distribution built from the tree pass
  `twine check`. The upload of 0.31.0 to PyPI was done by the workflow and checked on PyPI by the author.
* **Not verified**: the issue forms as GitHub renders them, until they are pushed.

### 2026-10-14: version 0.31.0

The last of the four brands: **Cisco Meraki MX**, both ways.

**Built**

* `parsers/meraki.py`: the answers of the Dashboard API (v1) for one network, in one JSON file under the names of
  their endpoints (the answer of the outbound table alone too). A zone per VLAN, with the subnets of its static
  routes (`lan` for a single LAN), and `internet`; policy objects and groups, `VLAN(n).*` and `VLAN(n).k`, host names
  as destinations; the outbound table first match from the LAN zones with its fixed default rule; layer 7 rules of
  ports and address ranges as denies before it, the others not converted; port forwarding, 1:1 and 1:many NAT as
  destination NAT and static NAT both ways, with their allowed remote addresses as rules from the internet; NAT to
  the uplink; NAT exceptions and passthrough mode with the inbound table; group policies, the cellular and VPN
  tables and the services of the MX said.
* `emitters/meraki.py`: a shell script for curl that writes the bodies, backs up each table and puts it (with
  `DRY_RUN=1` it writes the bodies only and needs no key): the outbound table, a rule of the model as many rules of
  the MX as it takes (one protocol, one IP version where a side is not any, one range of ports), kept to the
  networks of its zones, with a final deny where the source blocks the rest; port forwarding, 1:1 and 1:many NAT
  with the sources of the rules that allow all of them as allowed remote addresses.
* `--from` and `--to meraki`, `--inside-zone` and `--zone-network` for it, detection before AWS; the sample
  (`meraki_sample.json`, written by `tests/tools/make_meraki_sample.py`), 55 golden conversions, their audit and
  matrix.

**What the work made necessary**

* *Allowed remote addresses that never let in more.* They have no order and no deny. The emitter takes a rule into
  them only when it allows all of a NAT rule's ports to the public address, its destination zones hold the
  translated address and it can be written; a rule that blocks some of it first ends the list. A test of its own
  sends packets from the internet through what the script writes and checks that the model allows each one the MX
  lets in.
* *The judge decides the inbound side as well.* NAT exceptions and passthrough mode hand traffic from the internet
  to the inbound table; the random networks have both, with several uplinks.

**Review**

*Round 39* by the independent reviewer, with probe scripts, two fuzzers and a differential test of the allowed
remote addresses.

| | Finding | Fix |
|---|---|---|
| high | Emitter: rules that are not converted (unsupported, users, URL categories, applications, schedules) became allowed remote addresses | left out; one that blocks ends the list |
| high | Emitter: a rule that allows one port of a NAT range opened the whole range (5,748 differences in the reviewer's differential) | the rule must allow all of it |
| high | Emitter: the zones of rules from the internet were ignored, also the zone of the translated address | sources kept to their zones outside; destination zones must hold the translated address |
| high | Parser: a policy object or group named `any` became every address | renamed |
| high | Parser: in passthrough mode the inbound table was ignored | read before the allow of the rest |
| high | Parser: with NAT off on an uplink the allowed remote addresses stayed in force when the inbound table held only its default rule, or was missing | the inbound table decides; missing, NAT lets in nothing |
| high | Parser: the allow inside a VLAN had every zone as its source, the internet too, so every rule was dead without VLANs | the LAN zones only, none without them; `MERAKI_NO_LAN` |
| medium | Parser: NAT ports missing or `any`, `destinationPorts` as a string, read as every port or per character | not converted |
| medium | Parser: host bits in policy objects widened; a group of an object that is not read, a VLAN without a subnet, read as narrower denies | not converted |
| medium | Emitter: port forwards always on internet1 | the uplink of the source, or of the address |
| medium | Emitter: a rule between zones that names one zone on both sides was written as if the MX filtered that | said (`MERAKI_INTRAZONE`) |
| medium | Parser: the inbound table alone read as the outbound table | refused |
| low | Emitter: a deny that came out as no rule; DNAT ports that ended in a traceback or out of range; `DRY_RUN` needed the key; restoring a backup duplicates the Default rule. Parser: non-rules in the inbound table, naming that took quadratic time, host names as sources, lists inside allowed remote addresses | each refused, said or handled |

The fixes were not reviewed again; they have tests (`test_r39_*` in `test_meraki.py`). A rule that blocks every
service but some was found after them, by the NAT differential at more seeds, and is fixed and tested too.

**Verified, and not**

* The tests: 448 in `test_meraki.py`, the suite 6117. The parser against the judge: 500 random networks (VLANs
  with IPv6 and static routes, objects named `any` and with host bits, groups of them, layer 7 rules, several uplinks,
  NAT exceptions, passthrough mode and the inbound table), 300 packets each, and every rule the judge does not decide
  is not converted; a round trip (answers, model, script) of 80 more; the emitter against the model through the reader
  of its script: 40 random models exactly from the LAN, and 300 random NAT models where everything the MX lets in
  from the internet is allowed by the model. Run once at more seeds: 3,000 more networks against the judge, 600 more
  emitter models, 3,800 NAT models and round trips, none different.
* A mutation check with 78 ways to break the parser and the emitter: 59 caught at first; for 17 of the other 19
  tests were added (a Default rule that blocks, empty allowed remote addresses, the uplink of NAT with no SNAT rule
  and of 1:many NAT on a WAN address, a translated address in no zone given, rules that block and cannot be read or
  block other ports, ping and other ICMP types into 1:1 NAT, the fixed default rule, port 0, a service of every
  protocol, ICMP and ICMPv6 by IP version, host names among the sources of a rule that blocks, users, more than 64
  allowed remote addresses), which catch them. The last 2 change nothing: inbound rules from any zone come after
  the Default rule, which takes all traffic from the LAN, and the reasons of a rule are checked again before its
  sources are taken.
* **Not verified**: no call was made to a Dashboard, and no configuration of a real network was read: the inputs were
  written from the API specification and Meraki's documentation. How the inbound table and NAT exceptions decide
  traffic NAT lets in, what layer 7 rules act on, the IPv6 side of VLAN objects and the uplink `both` are assumed;
  the tests rest on the same reading.

### 2026-10-14: version 0.30.0

The third of the four brands: **Stormshield SNS** (version 4), both ways.

**Built**

* `parsers/stormshield.py`: the ConfigFiles of a firewall as a `.tar` or `.tgz` (what `decbackup` makes of a backup,
  or the folder packed); a backup itself (`.na`, encrypted) is refused with the command that opens it. The interfaces
  as zones; objects (hosts, ranges, networks, FQDN objects and hosts resolved by name, services, protocols, groups and
  service groups, nested, by name without regard to case), the objects of the interfaces (`Network_<if>`,
  `Firewall_<if>`, `firewall_all`, `Network_internals`, `Internet` by its definition); the active filter slot or the
  one named with `--policy`, after the global slot; rule lines read with a grammar of what is published (actions,
  `log`, `inspection`, `ipproto`, `proto`, `settos`, `route`, `from`, `on`, `to`, `port`, users, `!`, comments,
  separators), anything else not converted; `decrypt` and `log` left out; a global `deleg` of everything at its end
  read as the step to the local policy, one with conditions refused. The NAT rules of a slot are not read.
* `emitters/stormshield.py`: a script of serverd commands: objects with `update=1`, one filter slot emptied and
  written (a rule per interface pair and kind of service; `state=off` for what it cannot say), the defaults of the
  source as rules at the end, NAT (to an interface, a pool, a static address, static both ways, destination NAT), the
  slot renamed and not made active.
* `--from` and `--to stormshield`, `--policy` for the slot to read and `--target-policy N[:NAME]` for the slot to
  write, detection before the refusal of compressed input and before Sophos; the sample (`stormshield_sample.tgz`,
  written byte for byte the same by `tests/tools/make_stormshield_sample.py`), 55 golden conversions, their audit and
  matrix.

**What the work made necessary**

* *A grammar of what is known.* With the syntax of the files unpublished, every word the reader does not know makes
  the rule not converted; the judge of the tests requires that what it does not decide is not converted.
* *Archives as input.* A gzip that is not a Stormshield archive is still refused as before; a tar that is a Sophos
  export is still Sophos; members, sizes and the unpacked size are bounded.
* *One protocol per rule.* SNS rules carry one IP protocol, so the emitter splits by kind of service; the tests
  judge the pieces together against the model.

**Review**

*Round 38* by the independent reviewer, with probe scripts.

| | Finding | Fix |
|---|---|---|
| high | `tos N`, a match, was read as a setting: the rule matched everything | not converted; `settos` and `route` said on the rule (`STORMSHIELD_HANDLING`) |
| high | `Internet` was always "not `Network_internals`", whatever `[Internet]` said; computed before group names were resolved | by its definition, after the names; not converted where that cannot be read, or without a `network` file |
| high | A group that holds a member twice, or itself, hung the parser | each group looked at once; a group in itself not converted |
| medium | A gzip that cannot be read ended in a traceback for every source | refused |
| medium | Global slots with rules and no active one were left out silently | refused |
| medium | Empty names in lists (`from ,`), hosts with a prefix, networks with host bits, lines split at U+0085 and the like | not converted; lines split at line feeds only |
| medium | `Network_*` and `Firewall_*` (first address), bridges: not said | said on the rule (`STORMSHIELD_INTERFACE_OBJECTS`, `STORMSHIELD_BRIDGE`) |
| medium | Emitter: the order of NAT rules not reported; the script changes objects an active slot may use, and snscli goes on after a failed command | `NAT_ORDER` reported; said in the script and the report, with `CONFIG FILTER CHECK` |
| low | `deleg` in the local policy, tags across slots, options twice, `! !`, negated users, hosts resolved by a name that is no DNS name, unknown host options, Sophos tars with an `object` file, hard links, the number of members, scheduled slots; emitter: zone `Any`, names that clash once characters are replaced, a prefix of `Firewall_`, values with `<`, `>` or `#`, ports 0 to 65535, builtins in lists | each refused, said or handled |

The fixes were not reviewed again; they have tests (`test_r38_*` in `test_stormshield.py`).

**Verified, and not**

* The tests: 120 in `test_stormshield.py`, the suite 5614. The parser against the judge: 500 random firewalls (with
  global policies, custom `Internet`, groups with repeated members), 300 packets each, and every rule the judge does
  not decide is not converted; a round trip (ConfigFiles, model, script) of 60 more; the emitter against the model
  through the reader of its script: 40 random models, exactly.
* A mutation check with 51 ways to break the parser and the emitter: 40 caught at first; for 9 of the other 11 the
  random firewalls were widened (the objects of a bridge port) and tests were added (a `#` inside quotes, `!any`,
  empty names in a list of services, words after the services, a global `deleg` with conditions at its end, the
  defaults inside a zone of the target, a service of every protocol), which catch them. The last 2 change nothing: a
  line that is all comment is left out either way, and ICMP read as protocol 1 is the same.
* **Not verified**: nothing was run on a firewall, and no configuration of a real firewall was read: the inputs were
  written from Stormshield's documentation and the fragments its tools show. The syntax of rule lines beyond those
  forms, the layout of `slotinfo`, the IPv6 tokens of the commands that create objects and the NAT section are
  assumed or not read; the tests rest on the same reading.

### 2026-10-14: version 0.29.0

The second of the four brands: **Huawei USG** (USG6000, USG6000E, USG9500), both ways.

**Built**

* `parsers/huawei.py`: `display current-configuration`. Security zones and their interfaces (`local`, the firewall,
  not converted); address sets (masks, mask lengths, wildcards, ranges, IPv6, nested) and service sets (ports with
  `to` and several on a line, ICMP types, protocols, nested), each resolved once; the predefined services by their
  well-known ports; the rules of `security-policy`, first match, with zones, addresses, exclusions (taken out of what
  the rule names, or a negation), services (also written in the rule), `disable`, logging, and applications, users and
  time ranges carried; the defaults (`default action`, `default packet-filter intrazone enable`, V100R001) with the
  permit inside a zone as an explicit rule; `nat server` (ports, a protocol, static both ways, `zone`, `no-reverse`)
  before the policy, with the rules rewritten to the address as it arrives; `nat-policy` (easy-ip, address pools,
  no-nat) after it. The root system up to the first `switch vsys`; `policy interzone` and packet filters between zones
  refused. Lines are read by their indent and the `#` lines between blocks.
* `emitters/huawei.py`: commands for the system view. Zones (`trust`, `untrust` and `dmz` as they are, others with
  the prefix and a priority of their own), address and service sets, a rule of `security-policy` per rule in order
  (per zone for rules inside or between their zones only; all zones listed for any), `disable` first for what it
  cannot say; `default action permit` and rules that deny inside a zone where the source wants them; `nat server`,
  `nat-policy` and address pools; the zones' interfaces as comments.
* `--from` and `--to huawei`, detection before IOS; the sample (`huawei_sample.cfg`, written by
  `tests/tools/make_huawei_sample.py`), 52 golden conversions, their audit and matrix.

**What the work made necessary**

* *Two defaults in one model.* A USG denies between zones and passes inside one; the parser writes the second as a
  rule at the end, and the emitter leaves out the rules that deny inside a zone where a rule already decides all of it.
* *Indentation that means two things.* VRP prints the commands of the system view with a space, like the lines of a
  block. The reader goes by the `#` lines between blocks, keeps the lines of a rule in their policy, and looks for the
  flag that changes the default inside a zone at every depth.
* *A judge of the USG.* `test_huawei.py` builds random USGs as plain descriptions, writes them as current
  configurations, and decides packets from the description: `nat server`, the rules, the defaults; what it does not
  decide must be not converted in the model. The emitted commands are read back by a strict reader into the same
  description, also after a round trip from a USG.

**Review**

*Round 37* by the independent reviewer, with probe scripts.

| | Finding | Fix |
|---|---|---|
| high | `default packet-filter intrazone enable` printed with a space after another command of the system view was a line of that command: the permit inside a zone was converted | looked for at every depth; a line after a `#` line is a command of the system view |
| high | The rules of virtual systems were read into the root's policy | the root is read up to the first `switch vsys`; a `switch vsys` inside a block is refused |
| high | `nat server` was written for NAT rules with sources, destination zones or several source zones, which it cannot say, and the rules rewritten for it | not written; the rules are left as the model names them |
| medium | A NAT service that cannot be read, or holds nothing, gave a `nat server` of every protocol | not written |
| medium | `*-address-exclude any` next to addresses was ignored | the rule matches nothing: not converted |
| medium | Nested sets were resolved again for every reference: a 2.5 kB configuration took minutes | each set resolved once; service sets flattened, at most 10,000 entries |
| medium | Rules of any zone were written without zones, so they also matched traffic to the firewall | the zones are listed; a source without zones is said (`HUAWEI_NO_ZONES`) |
| medium | A rule written disabled had its conditions before `disable`, and the side it could not say left out (any) | `disable` first; that side an address no forwarded packet has |
| medium | Lines of a rule outside their place were lost or read as other rules' | every line of a rule stays in its policy; a rule outside one is refused |
| medium | V100R001, where traffic inside a zone meets the default policy, was read as V500 | read from the version line (`HUAWEI_V100`) |
| low | Zoneless sources, protocol 0, a wildcard of all ones, rule groups as information only, `?` and blank descriptions in the output, `quit` lines not read, a NAT origin with one rule written and one not | each said, refused or handled |

Acted on as well, from the reviewer's suspicions: an exemption above a destination NAT keeps the `nat server` from
being written (a USG does it first); packet filters between zones (a router, an older USG) are refused.

The fixes were not reviewed again; they have tests (`test_r37_*` in `test_huawei.py`).

**Verified, and not**

* The tests: 122 in `test_huawei.py`, the suite 5438. The parser against the judge: 400 random USGs (200 with the policy
  only, 200 with NAT), 300 packets each, and every rule the judge does not decide is not converted; a round trip
  (USG, model, USG commands) of 60 more; the emitter against the model through the reader of its output: 40 random
  models, exactly.
* A mutation check with 63 ways to break the parser and the emitter: 50 caught at first; for 10 of the other 13
  the random USGs were widened (wildcards with host bits, lines FWShift does not know, rules without an action or with
  a zone that is not in the configuration), the judge now also requires that what it does not decide is not
  converted, and tests were added (the zone and protocol of a `nat server`, a command of the system view after a `#`
  line, emitted rules for the inside address, an origin with one NAT rule written and one not, a static translation
  both ways limited to a zone), which catch them. The last 3 change nothing: ports 0 to 65535 are every port, and a
  set that holds a set that cannot be read is not converted whether or not its addresses are kept.
* **Not verified**: nothing was loaded on a firewall, and no configuration of a real firewall was read: the inputs were
  written from Huawei's documentation. The indentation of display output, the ports of the predefined services, the
  form of IPv6 entries in address sets and the order of rule groups are assumed; the tests rest on the same reading.

### 2026-10-14: version 0.28.0

The first of four brands asked for after Google Cloud: **Cisco IOS and IOS XE** routers, both ways.

**Built**

* `parsers/ios.py`: the running configuration of a router. Interfaces (addresses, the lists bound in and out for
  IPv4 and IPv6, the zone, the NAT role, VRFs, classic inspection); access lists numbered and named, standard,
  extended and IPv6, in the order of their sequence numbers, with wildcard masks (non-contiguous ones as up to 256
  ranges), object groups of networks and services, port operators and the port names of each protocol, ICMP names,
  remarks; the zone-based firewall (zones, zone pairs, inspect policies, class maps with access lists, `match
  protocol` through Port-to-Application Mapping and `ip port-map`, nested class maps, `class-default`); NAT
  (`ip nat inside source` static, network, port, to an interface; a list to an interface or a pool). A connection
  passes the inbound list, NAT, the outbound list and the zone-based firewall: where only inbound lists decide each
  becomes the rules of its zone, otherwise the lists are composed for each pair of zones, with the outbound list and
  the zone-based firewall rewritten through NAT into the addresses as they arrive. What is not understood makes its
  entry not converted.
* `emitters/ios.py`: commands for the zone-based firewall. A zone per zone (prefixed), an access list (IPv4 with
  object groups, IPv6 with prefixes) and an inspect class map per rule, an inspect policy per zone pair in the order
  of the rules with `class-default` and, for a default that allows, a class that inspects the rest; allow rules
  inspect TCP, UDP and ICMP and pass the rest; zone pairs from a zone to itself where the source decides traffic
  inside a zone otherwise. The zone membership and NAT (static address, network and port; port translation to an
  interface or a pool) are comments.
* `--from` and `--to ios`, detection before the ASA (which shares some lines with IOS); the sample
  (`ios_sample.cfg`, written by `tests/tools/make_ios_sample.py`), 49 golden conversions, their audit and matrix.

**What the work made necessary**

* *Three lists per connection.* An IOS router decides a connection with up to three first-match lists, and the
  second one sees other addresses than the first. The parser keeps the common case (inbound lists only) as it is
  written and composes only where it must; composing leaves out what an entry above already takes, so that rules
  that can never match are not written.
* *Grouping without names.* The composed lists of the pairs of zones that are alike are made once; their keys leave
  out what names an interface, or every pair would differ.
* *A judge of the router.* `test_ios.py` builds random routers as plain descriptions, writes them as running
  configurations in the classic and the IOS XE form, and decides packets from the description: lists, NAT
  (static, port, dynamic with a list), the zone-based firewall. The emitted commands are read back by a strict reader
  of their own into the same description.

**Review**

*Round 36* by the independent reviewer, with probe scripts.

| | Finding | Fix |
|---|---|---|
| high | A reflexive list that holds only `evaluate` was read as empty, so it passed everything | `evaluate` is an entry that matches no new connection: the list ends in its implicit deny |
| medium-high | NAT the parser does not read (`ip nat inside destination`, a route map, a port translation to a DHCP interface, outside NAT) was ignored for connections from outside: denies of an outbound list or the zone-based firewall written for the inside address were lost | NAT not read makes the entries it could change not converted, in both directions; `ip nat inside destination` is read as not converted |
| medium | `ip port-map` took every number on its line: `from 8000 to 8100` became two ports, a number in the description a port | read by its grammar; anything else makes the protocol not converted |
| medium | Emitted zone names had no prefix: a zone `default` became the default zone of IOS XE, a zone that exists took in its zone pairs | zone names prefixed; `default` and `self` reserved |
| medium | Composed lists were not grouped (the name of the empty outbound list named the interface): 55,000 rules for 50 interfaces | the name left out of the key; at most 100,000 rules, then the pairs left are blocked (`IOS_COMPOSED_LEFT_OUT`) |
| low | Ports above 65535 in `ip port-map` or a port translation ended in a traceback | read as not converted; the parser catches what slips through |
| low | `ip access-group common ...` was ignored, so the interface passed everything | not converted and said (`IOS_ACL_NOT_READ`) |
| low | A layer-7 policy under an inspect class was ignored without a word | said on the rule (`IOS_LAYER7`) |
| low | Text of zone and interface names went into the output as it was; `intrazone_allow` of a zone was ignored | non-printable characters replaced; the zone's own default honoured |

Acted on as well, from the reviewer's suspicions: a class map without match statements, or over a list without
entries, is not converted; `zone security default` alone puts the interfaces in no zone into it; protocol 0 is not
converted (IOS may read it as every protocol) and not written; a banner is not configuration; the pool of a port
translation is written with a prefix of at most /30.

The fixes were not reviewed again; they have tests (`test_r36_*` in `test_ios.py`).

**Verified, and not**

* The tests: 65 in `test_ios.py`, the suite 5262. The parser against the judge: 480 random routers (120 each with
  lists only, with the zone-based firewall, with NAT, and mixed), 300 packets each; the emitter against the model
  through the reader of its output: 40 random models, exactly where no narrowing finding is raised and never allowing
  more where one is.
* A mutation check with 54 ways to break the parser and the emitter: 38 caught at first; for 14 of the other 16 the
  random routers were widened (port boundaries, UDP port names, wildcards of all ones and with host bits, ICMP codes,
  denies in the lists of class maps) and tests were added (a class-default without an action, outside addresses of
  NAT in an outbound list, the denies of a NAT list, the default of the source in the output), which catch them; the
  emitter's comparison is now exact also where it lets protocols through with pass. The last 2 change nothing: a
  wildcard of all ones read in two halves is the same, and the services of one IP version never hold the ICMP of
  the other.
* **Not verified**: nothing was loaded on a router, and no configuration of a real router was read: the inputs were
  written from Cisco's documentation. Which addresses the zone-based firewall sees under NAT, how `show
  running-config` prints numbers it has names for, and the system table of Port-to-Application Mapping are taken
  from there or assumed; the tests rest on the same reading.

### 2026-10-14: version 0.27.0

The second of the two releases asked for after Forcepoint: **Google Cloud**, its VPC firewall rules and network
firewall policies, both ways, and its Terraform resources (`terraform-google`).

**Built**

* `parsers/gcp.py`: the JSON of gcloud for one VPC network (`firewall-rules list`, `network-firewall-policies describe`
  global and regional, `networks describe`, `instances list`), in one object, an array or alone; also the answer of
  `networks get-effective-firewalls` and hierarchical policies (`firewall-policies describe`). The steps in Google
  Cloud's order (hierarchical, system, then the VPC rules and the network policies in the enforcement order of the
  network, then the implied rules); VPC rules by priority with a deny first at a tie; policy rules by priority, with
  `goto_next` cut out of the rules below it; targets (tags, service accounts, regions of a regional policy) and source
  tags as the addresses of the instances; egress and ingress composed between instances; external addresses as static
  NAT. What the export does not resolve (secure tags, address groups, FQDN, geography, threat intelligence, network
  context) makes its rule not converted.
* `emitters/gcp.py`: a shell script of gcloud commands (`DRY_RUN`, `GCLOUD_OPTS`, stops on a policy of the same name)
  that creates one global network firewall policy, associated with nothing: each rule of the model per IP version for
  ingress and egress, at priorities from 1000 in steps of 10, ending in the default of the source. Zones become the
  networks of `--zone-network`, as for NSX. ICMP types and source ports cannot be written: left out of an allow rule,
  widened in a blocking one.
* `terraform-google`: `parsers/terraform.py` turns `google_compute_firewall`, `google_compute_network`, the global and
  regional network firewall policies (with their rule, association and `_with_rules` resources) and
  `google_compute_instance` into the answers of gcloud, which `parsers/gcp.py` reads; what a plan does not know is
  handed on by name (`fwshiftUnknown`). `emitters/terraform.py` writes the policy of the gcp emitter as a
  `google_compute_network_firewall_policy` and its `_rule` resources.
* `--from` and `--to gcp` and `terraform-google`, detection, `--policy` for the network; the samples (`gcp_sample.json`
  by `tests/tools/make_gcp_sample.py`, `terraform_google_sample.json` by `make_terraform_samples.py`), 96 golden
  conversions, their audit and matrix.

**What the work made necessary**

* *Two lists per connection.* As for AWS and Azure, a connection between two instances passes two lists. Google Cloud
  adds steps within each list, so each list is first flattened (steps, `goto_next`), then the two are composed.
* *`goto_next` as subtraction.* It is the one action a first-match list has no word for; the rules after it in its
  policy, less what it matches, say the same. Where the subtraction gets too complex, the rules after it are not
  converted rather than guessed.
* *A judge of its own.* `test_gcp.py` decides packets from the gcloud JSON directly (steps, tags, instances, regions,
  external addresses), sharing no code with the parser; a second judge reads the emitted script.

**Review**

*Round 35* by the independent reviewer, with probe scripts.

| | Finding | Fix |
|---|---|---|
| high | The answer of `get-effective-firewalls` lost its policies (`firewallPolicys`) | read: hierarchical and system policies first (`GCP_EFFECTIVE`) |
| high | terraform-google: regional policies of one name in different regions were merged, their rules mixed | named by region and name; a name several regions have, without a region, is not read and said (`TERRAFORM_POLICY_AMBIGUOUS`) |
| medium | Target or source tags and service accounts a plan does not know became a text that names no instance: a deny vanished | handed on as not known: the rule is not converted; so is a tag rule while an instance's tags are not known |
| medium | A hierarchical policy was left out as not associated with the network | read as the first step (`GCP_HIERARCHICAL_READ`); its rules for other networks (`targetResources`) left out |
| medium | The emitter's limit on address ranges could write the IPv4 half of a rule and refuse the IPv6 half, and counted intervals, not ranges | checked first, for both versions, in ranges |
| low | Services the model cannot name after the rules above made a rule vanish | the rule is written not converted |
| low | `null` or empty entries in lists of ranges, tags and ports were left out: a list could become any | never any: the rule is not converted |
| low | A rule that applies to no instance vanished without a word | skipped and said (`GCP_NO_INSTANCE`) |
| low | The network was named from the policies before the VPC rules | VPC rules first |
| low | Docstrings of the Terraform files named AWS and Azure only | updated |

Acted on as well, from the reviewer's open questions: an ingress rule without a source whose destination ranges are
IPv6 is every IPv6 address (and an egress rule without a destination likewise), in the parser and in the judge; a
`disabled` that is neither true nor false makes the rule not converted; a policy without its rules (the answer of
`list`) is said (`GCP_POLICY_WITHOUT_RULES`).

The fixes were not reviewed again; they have tests (`test_r35_*` in `test_gcp.py` and `test_terraform.py`).

**Verified, and not**

* The tests: 83 in `test_gcp.py`, 146 in `test_terraform.py`, the suite 5146. The parser against the judge:
  250 random networks (VPC rules of both directions with tags, service accounts, ranges of both versions, disabled
  rules; global and regional policies with `goto_next`; instances in several regions with IPv6, alias ranges and
  external addresses), 300 packets each, and the sample with 5,000; the same networks as Terraform states and raw
  states (100); the emitter against the model through the script judge: 65 random models, exactly where no narrowing
  finding is raised and never allowing more where one is; the HCL of terraform-google likewise (25).
* A mutation check with 47 ways to break the parsers and the emitter: 38 caught at first; tests were added for 7 of
  the other 9, which catch them (ports on ICMP, source tags while an instance's tags are not known, a policy rule
  without a source, `goto_next` cut and not worked out, a regional policy without a region, a policy rule whose
  `disabled` a plan does not know); the random judge test was widened, as the cut of `goto_next` mattered in few of its
  packets. The last 2 change nothing an input can show: Google's own rules sit at the end of a policy (from
  2147483644), so reading a few priorities more of the reserved range finds none; and no input of the tests leaves
  services after the cuts that the model cannot name.
* **Not verified**: no gcloud command of a script was run, no Terraform has read the output, and no export of a real
  project was read: the inputs were written from Google's API reference and documentation. The order of the steps, what
  a tag matches, the default source of a rule and the shape of the answers are taken from there; the tests rest on the
  same reading.

### 2026-10-14: version 0.26.0

The first of two releases asked for after Forcepoint: **Terraform**, for the clouds FWShift already reads, AWS and
Azure, both ways. Google Cloud follows in 0.27.0, with its Terraform resources.

**Built**

* `parsers/terraform.py`: the JSON of `terraform show -json` (format version 1) of a state or a saved plan, and the
  raw state of version 4. Modules, `count` and `for_each` followed; data sources and deposed objects left out. The
  resources of hashicorp/aws (groups with inline rules, the three kinds of separate rule, network ACLs with inline and
  separate entries and associations, interfaces, attachments, instances, Elastic IPs, subnets, VPCs, prefix lists and
  their entries) and of hashicorp/azurerm (network security groups with inline and separate rules, the associations
  with subnets and interfaces, application security groups and theirs, interfaces, subnets, virtual networks with
  inline subnets, peerings) become the answers of the AWS or the Azure CLI, which `parsers/aws.py` and
  `parsers/azure.py` read. Echoes of a refresh are read once; a separate resource wins over an inline copy that says
  otherwise (`TERRAFORM_CONFLICT`). In a plan: `after_unknown` and missing attributes say what is not known; an id
  that is not known is the address of its resource, worked out from the references of the configuration (also in a
  module with `count`); what is deleted or replaced is taken out of the inline lists that still repeat it; an
  errored plan is refused, an incomplete one said. What neither the plan nor the configuration tells makes its rule
  not converted (`TERRAFORM_UNKNOWN`), never any address or port.
* `emitters/terraform.py`: `terraform-aws` is the AWS emitter with HCL instead of CLI calls (a subclass; `aws.emit`
  got a `prepare()` for it): an `aws_security_group` per group and an `aws_vpc_security_group_ingress_rule` or
  `_egress_rule` per address block and service, the attachments as comments and an output. `terraform-azure` writes
  the ARM template of the Azure emitter as `azurerm_network_security_group` resources with inline rules, application
  security groups by name as data sources, the networks as comments and an output. HCL strings with `${` and `%{`
  doubled.
* `--from` and `--to terraform-aws` and `terraform-azure`, detection before the AWS and Azure JSON (by the managed
  resources it holds), `--policy` for the VPC; the samples (`terraform_aws_sample.json` and
  `terraform_azure_sample.json`, written by `tests/tools/make_terraform_samples.py`), 84 golden conversions, their
  audit and matrix. Lone surrogates in names no longer break writing the output.

**What the work made necessary**

* *One reading per cloud.* Terraform's resources say nothing new about how a VPC or a network security group decides
  traffic. Turned into the CLI answers, they go through the parsers that already have their judges and their reviews;
  what is Terraform's own (echoes, plans, unknowns) is the new file's business.
* *Plans are half known.* A plan leaves out what is computed at the apply. An id that is not known still names one
  resource, so the address can stand for it everywhere it is referred to; everything else that is not known is not
  converted. The configuration a plan shows has no dynamic blocks, so a list of rules nothing explains is not known
  either, unless separate resources fill it.
* *An HCL reader for the tests.* There is no Terraform here. The tests read the emitted HCL with a small reader of
  their own (blocks, attributes, strings with every escape, references, objects) and hand the result to the judges
  of the AWS script and the Azure template.

**Review**

*Round 34* by the independent reviewer, with probe scripts.

| | Finding | Fix |
|---|---|---|
| high | A plan still read rules it deletes or replaces, from the inline list of their group (and a deleted attachment from the interface) | taken out of the echoes |
| high | An inline copy that says otherwise than its separate resource (Azure by name, a network ACL entry by number) won silently | the separate resource is read, said (`TERRAFORM_CONFLICT`) |
| high | Rule lists of a plan with unknown elements, or unknown and not in the configuration, became fewer rules: a deny lost | not known: the group or ACL not converted, unless separate resources fill the list |
| high | Unknown values of fields not listed as references (ports, protocol, rule number, names) were read as null: any port, any ICMP type, entry 0 | `after_unknown` and every field of a rule; an unknown value makes the rule or entry unreadable; no dedupe on an unknown name |
| medium | Entries of a network ACL not in the state were dropped (no VPC) while the note said they were read | read for the VPC of the conversion; the note says what may be missing |
| medium | An errored or incomplete plan was read without a word | refused; `TERRAFORM_INCOMPLETE` |
| medium | A lone surrogate in a name broke writing the output | written escaped |
| medium | The docs and the version were not done yet | done |
| low | `TERRAFORM_UNKNOWN` spoke of a plan for a state; computed `subnet_ids` of a new ACL counted as unknown | worded per input; computed lists that separate resources fill are theirs |
| low | A data source of the other provider made a state of two providers; an empty state was not recognised | managed resources only; recognised |
| low | `--policy` was ignored for `terraform-azure` | refused |
| low | azurerm 4 needs a subscription id | a variable for it |

The fixes were not reviewed again; they have tests (`test_r34_*` in `test_terraform.py`).

**Verified, and not**

* The tests: 117 in `test_terraform.py`, the suite 4938. The parser against the judges of `test_aws.py` and
  `test_azure.py`: 200 random VPCs written as states and raw states (inline, legacy and single rules, echoes, default
  groups, modules, count and for_each, instances and interfaces, attachments, Elastic IPs, ACLs inline and separate),
  80 of them as plans that create some of their groups, and 200 random sets of Azure groups, 300 packets each; the
  emitters against the model through the HCL reader: 90 random models; the samples against CLI answers written by
  hand.
* A mutation check with 49 ways to break the parser and the emitters: 33 caught at first; tests were added for 12 of
  the other 16, which catch them (data sources and deposed objects of a raw state, what `after_unknown` marks, a
  conditional between two groups, the inline rules of a group a plan does not know, groups of other accounts, ICMPv6
  of an unknown type, an Elastic IP of a second address, unknown ACL entries, an entry a plan deletes, an association
  that moves a subnet, the severity of a group not in the state). The last 4 change nothing an input can show (an
  attribute in the planned values is known; a configuration block without a required attribute is invalid and
  unreadable either way; the AWS parser reads an address whichever key holds it; an ICMP code left out is any code
  either way).
* **Not verified**: no Terraform has read the output, and no state of a real deployment was read: the inputs were
  written from Terraform's documentation and source and the providers' documentation. What a refresh echoes, which
  attributes a plan leaves out and how a dynamic block shows are taken from there; the tests rest on the same reading.

### 2026-10-14: version 0.25.0

The last of three brands asked for after the plan of 2026 (`TODO.md`): **Forcepoint NGFW**, both ways, through the
REST API of its Security Management Center. And the answer to an outside security review.

**Built**

* `parsers/forcepoint.py`: the answers of the SMC REST API for one firewall policy (one JSON document per line, list
  answers named by `fwshift_list`). The policy and its templates up to the predefined one, the four rule lists in the
  order of the insert points (rules that name none at the only insert point above, or last with `RULE_ORDER`);
  sections as tags; Allow, Discard, Refuse; Continue, whose logging goes to the rules below that may match the same
  traffic (also into the sub-policies they jump to); jumps flattened, each rule of the sub-policy limited to the
  jump rule; NONE cells; zones, users, applications and URL categories in cells (a rule per combination), match
  expressions; hosts with their other addresses, networks without *broadcast* (in a rule cell), ranges, groups,
  expressions (union, intersection, the exclusion of one element), domain names; each rule pinned to its IP
  version, by the part of its groups of that version or, for a negated side, the addresses of that version it
  leaves; NAT rules (static destination with ports, static and dynamic source, `$$ Default NAT Address`, no NAT);
  the XML export refused with the way to the API.
* `parsers/smc_dump.py` and `fwshift script forcepoint-dump`: the read-only program that logs in, fetches the policy
  and everything it names (only the fields a rule or an element names others in, only links to the SMC that was
  named), writes the answers one per line and logs out.
* `emitters/forcepoint.py` and `emitters/smc_loader.py`: a Python script, the loader and the policy as data. The
  plan holds the elements in the order they are created, the zones, what must exist already, and the rules of each
  list; a rule goes into the list of each IP version it can match, with the part of its groups of that version;
  zones and addresses on one side are match expressions; a negated side an expression; what cannot be written is
  written disabled, with NONE in a cell left empty. The loader looks up every element first, reuses one only when
  it matches exactly what it would create, stops on anything else, creates, adds the rules each after the one before
  (`add_after`), reads each rule and each list back, journals call by call and undoes; it installs nothing.
* `--from forcepoint`, `--to forcepoint`, `--target-template`, `--policy` for it, detection; the sample
  (`forcepoint_sample.json`, written by `tests/tools/make_forcepoint_sample.py`), 39 golden conversions, its
  audit and matrix.
* Security, after the review of October 2026 (`docs/security/SECURITY_REVIEW.md`): every input is read up to a
  limit (1024 MiB, `FWSHIFT_MAX_INPUT_MB`); the workflows pin their Actions to commits, grant the least permissions,
  keep no token in the checkout and check the release tag strictly; a release carries `SHA256SUMS`; the README opens
  its use with a short procedure (*Using it safely*).

**What the work made necessary**

* *No export to read.* The SMC answers one element at a time and its XML export has no published format. Rather
  than guess at the XML, FWShift ships the program that asks the API, and reads exactly what it writes.
* *Two IP versions, one model.* An SMC keeps IPv4 and IPv6 rules apart, and "any" in the model is both. Each rule
  read says which version it is for; each rule written goes where it can match, with groups cut per version, and
  translations for both versions are not guessed at.
* *A test SMC.* The loader and the dump program run against a made-up SMC (`tests/fake_smc.py`): what the loader
  creates there, the dump program reads out, and the judge (`helpers.ForcepointSmc`) decides packets from those
  answers. So the emitter is checked through the same reading as the parser, by code that shares nothing with it.

**Review**

*Round 33* by the independent reviewer, with probe scripts.

| | Finding | Fix |
|---|---|---|
| high | Emitter: an interzone rule whose zones are all one zone was written as a rule inside that zone | not written (`RULE_TYPE_EMPTY`) |
| high | Emitter: the ports of an application were kept per application, not per IP version: a deny of `ping6` matched nothing | per application and IP version; one that cannot be written disables the rule |
| high | Loader: an existing element was reused when the fields it was sent matched, whatever else it held (a host with another address) | every field that decides what an element matches, on both sides |
| high | Parser: members of a cell that are not hrefs were dropped, and an empty cell or match expression read as any | unsupported |
| medium | Dump program: a list that could not be read was written as an empty one | left out, so the parser reports it missing |
| medium | Parser: names it made up (`X IPv4`) could be those of an element of the SMC | names of their own |
| medium | Parser: a zone the input does not hold made an enabled rule of a zone of that number | unsupported |
| medium | Emitter: a negated group that holds a host name was written as an expression of it | disabled (`NEGATED_FQDN`), groups looked into |
| medium | Parser: a destination port translation without an original port was lost | every port to the translated one |
| medium | Dump program: entry points on another host were followed, with the session cookie | refused |
| medium | Loader: an element the SMC created without saying where was not reported | named in what the run leaves |
| low | Parser: a NAT rule of the IPv4 list whose addresses do not say so | `IP_FAMILY` |
| low | Parser: `{"link": 5}` escaped as a traceback | a parse error |
| low | Parser: a TCP service with a last port and no first one, or ports 0 to 0 | unsupported |
| low | Emitter: NAT with a pool of both IP versions wrote the IPv4 pool into the IPv6 list | not converted |
| low | Loader: a rule the SMC holds otherwise than sent (enabled, action) was not noticed | each rule read back |
| low | Loader and dump program: several Set-Cookie headers kept only the last | all of them |
| low | Parser: dynamic source NAT without addresses became a rule without NAT | unsupported |

The fixes were not reviewed again; they have tests (`test_r33_*` in `test_forcepoint.py`).

**Verified, and not**

* The tests: 185 in `test_forcepoint.py`, the suite 4733. The parser against the judge: 60 random policies
  (templates of their own, sections, Continue, jumps, zones, match expressions, expressions, networks without
  broadcast, NONE cells, IPv6), 400 packets each, and 40 for NAT; the emitter against the model through the made-up
  SMC: 40 random models with every combination of defaults; the sample written, loaded, read out and judged, and
  read again.
* A mutation check with 51 ways to break the parser, the emitter, the loader and the dump program: 33 caught at
  first; tests were added for 14 of the other 18, which catch them (a disabled Continue rule, a rule without an
  action, closing logs at level none, two negations through a jump, a jump that matches nothing, services not within
  the jump rule, the second insert point of a template, the IP version of a NAT rule, a negated "any" of one version,
  ICMP only in the IPv4 list, a range of ports to one port, an existing policy, a missing alias, rules in another
  order). The last 4 change nothing a policy can show (a Source VPN match of the kind `normal` is unsupported either
  way; a negated "any" a parser never makes; a merged zone left out twice; a guard behind the reasons that disable a
  rule).
* **Not verified**: neither program has talked to a real SMC, and no answer of a real one was read: the inputs were
  written from the API guide and the clients Forcepoint publishes. What Refuse sends, how a zone in a cell and a
  network without broadcast in a NAT rule match, and whether an expression may stand in a match expression are
  assumed; the judge rests on the same reading, so a misreading would be in both.

### 2026-10-14: version 0.24.0

The second of three brands asked for after the plan of 2026 (`TODO.md`):
**OPNsense**, 24.7 to 26.7, both ways.

**Built**

* `parsers/opnsense.py`: `config.xml` of OPNsense 24.7, 25.1, 25.7, 26.1 and
  26.7, told apart by the version of the firewall model. A normalizer brings
  it into the form the pfSense reader reads: flags as each series reads them,
  the rules of *Rules [new]* (lists of addresses one rule per pair, upper-case
  protocols, ICMPv6 types by number, *received-on*) and of `<filter>` in the
  order of OPNsense's priorities, quick or not on every tab, port forwards of
  both forms (with *Pass* and *Register rule*), Source NAT and 1:1 NAT of the
  newer model. A subclass of the pfSense reader does the rest: aliases of the
  newer model as pf tables (entries with `!` worked out, disabled aliases
  empty, `__lan_network` and its like), the link-local network in rules for
  IPv6, the private networks of each series, the IPv6 switch of 26.1, NAT in
  OPNsense's order, the dead sections OPNsense migrated.
* `emitters/opnsense.py`: the pfSense emitter's decisions in the form of one
  series (`--target-version`, 26.7 by default): rules of *Rules [new]* with
  uuid5 identities and sequence numbers, aliases of the newer model (host
  names in host aliases, names with a letter first), port forwards of the old
  form up to 25.7 and of the newer from 26.1, Source NAT and 1:1 of the newer
  model; *received-on* for a leading deny between named zones (26.7); what a
  series cannot say disabled (`OPNSENSE_ICMP_TYPES`, `OPNSENSE_SCTP_PORTS`).
* `--from opnsense`, `--to opnsense`, `--target-version`, detection of an
  OPNsense configuration (the pfSense parser points to it), and
  `--interface-address` for it.
* `tests/test_opnsense.py` (122 tests): a judge of an OPNsense
  (`helpers.OPNsense`) that reads a configuration itself, both kinds of rule,
  aliases as tables, port forwards, Source NAT, 1:1 NAT and the restore of
  areas; the sample (`opnsense_sample.xml`, written by
  `tests/tools/make_opnsense_sample.py`), 37 golden conversions, its audit and
  matrix.

**What the work made necessary**

* *The pfSense reader, reused.* Most of what pfSense does with a
  configuration holds for OPNsense. Rather than a second reader, the
  configuration is brought into the form the pfSense reader takes, and a
  subclass overrides what differs; the emitter likewise. The parts of the
  pfSense emitter that decide names and keywords became overridable
  (`NAMES`, `keywords_of`, `emit_with`), and one of its decisions turned out
  wrong for pfSense too: an interface word in the source of an outbound NAT
  rule was wrapped in an alias as if it were an alias with `opt` in its name.
* *Flags that differ by series.* An empty element means "off" in most places,
  `<not/>` changed meaning in 26.1, and *Block private networks* in 25.7; a
  file of 24.7 to 25.7 does not say which of the three wrote it. Where they
  differ FWShift takes the reading that blocks more and says so.
* *The link-local network.* OPNsense adds fe80::/10 to the network of an
  interface in a rule for IPv6, and splits a rule for both versions before it
  does. The model holds it; the writer uses the word of an interface only
  where OPNsense makes of it what the model holds.

**Review**

*Round 32* by the independent reviewer, with probe scripts.

| | Finding | Fix |
|---|---|---|
| high | Emitter (pfSense and OPNsense): outbound NAT from the network of an `optN` interface was written as an alias holding the word, a host name to the firewall: the rule matched nothing | a word stays a word |
| high | Parser: a quick tab rule for both directions became a floating rule, ahead of every group and interface rule | split: the half for what arrives keeps its place, the half for what leaves is a leaving rule |
| high | Parser: groups of one sequence were taken group by group; OPNsense takes the newer kind of all of them first | sorted by (sequence, kind, order) |
| medium | Parser: leaving rules after Source NAT or 1:1 NAT of the newer model were not flagged as matching the translated source | those count for `_translating_zones` |
| medium | Parser: a disabled port alias inside another made the rule not loaded | it adds nothing to the other |
| medium | Parser: a negated source of a manual outbound NAT rule was dropped | the NAT rule is not converted, as for a negated destination |
| medium | Parser: a NAT target `wanip` on a rule of another interface was read as the address of the rule's interface | the address of the interface named |
| medium | Parser: a port forward on several interfaces was not loaded | one per interface; the note counts forwards |
| medium | Parser: a legacy rule without a source or destination was not loaded | any |
| medium | Parser: a one-way 1:1 rule was taken before Source NAT, manual and automatic NAT | after them (priority 500) |
| medium | Parser: an ICMPv6 rule of the old kind took `icmptype`, which OPNsense uses for ICMP | left out |
| medium | Emitter: host names in an alias of type network | an alias of type host of their own, held by the other |
| medium | Emitter: alias names starting with a digit | a letter first (`NameRules.start_letter`) |
| medium | Emitter: the word of an interface network in a rule for IPv6, to which OPNsense adds fe80::/10 | the addresses, unless the model holds the link-local network too (`OPNSENSE_LINK_LOCAL` where they are not known) |
| low | Parser: fe80::/10 only in rules for IPv6 only; OPNsense splits `inet46` first | in the IPv6 half too; not for a legacy rule without a family |
| low | Parser and judge: an empty BooleanField read as true in places | false, as the models read it |
| low | Emitter: aliases of the networks of interfaces written as type host | network |
| low | Parser: a disabled rule of an unknown type refused the file | left out (`OPNSENSE_DISABLED_ODD`) |
| low | Parser: a negated `<key>ip` in a rule for IPv4 on an interface without IPv4 was not loaded | every IPv4 address |
| low | `OPNSENSE_RESTORE` did not say that the rules area takes the static route bypass with it; the rate limit of 26.7 was not read | said; unsupported |
| low | pfSense: `pfsync` is protocol 240, not 249 | 240 (parser and judge) |

The fixes were not reviewed again; they have tests (`test_r32_*` in
`test_opnsense.py`), and the random generators now make the cases the review
found (tab rules for both directions, groups of one sequence, a disabled port
alias in another, a rule without a destination, `icmptype` in an ICMPv6 rule,
Source NAT to the address of another interface).

**Verified, and not**

* The tests: 122 in `test_opnsense.py`, the suite 4506. The parser against the
  judge: 70 random configurations per series (both kinds of rule, aliases with
  exclusions, disabled aliases, groups, flags), 300 packets each, and 60
  random NAT configurations per series; the emitter against the judge: 50
  random models across the five series; a round trip OPNsense to OPNsense
  per series, and pfSense to OPNsense against the pfSense judge (rules,
  floating rules, NAT).
* A mutation check with 49 ways to break the parser and the emitter (3 did not
  apply to the code as it was): 42 caught at first; tests were added for the
  other 4, which catch them all (a rule of the newer kind without an IP
  version, a port forward of the newer form that passes by itself, a negated
  destination of Source NAT, the order of the entries of an alias that leaves
  addresses out).
* **Not verified**: nothing was restored on an OPNsense, and no backup of a
  real one was read (the inputs were written by hand from the models and the
  code). What a restore does, how the GUI writes empty flags and lists, and
  the priorities are read in the code, not seen; the judge is written from
  the same reading as the parser, so a misreading of OPNsense would be in
  both.

### 2026-10-13: version 0.23.0

The first of three brands asked for after the plan of 2026 (`TODO.md`):
**MikroTik RouterOS**, 6 and 7, both ways.

**Built**

* `parsers/routeros.py`: the output of `/export` (compact, `terse`,
  `verbose`; lines continued with a backslash, inside quoted strings too;
  every escape of the scripting language). The `forward` chains of `/ip` and
  `/ipv6 firewall filter`, custom chains flattened with the conditions of the
  nftables parser, and a `return` taken away exactly where addresses,
  protocols or ports say what returns (`_split_without`: one condition per part
  in which the two differ). Interface lists as zones when the lists the rules
  use do not overlap, else interfaces; address lists as groups (host names
  as host name objects); the default accept; `connection-nat-state=!dstnat`
  as allow rules for each port forward ahead of the deny, where that is exact;
  `dst-nat`, `netmap`, `masquerade`, `src-nat`, `same`, no-NAT,
  `dst-address-type=local`; the router's own chains, raw, mangle, UPnP,
  bridges, offloading and lists filled at run time reported.
* `emitters/routeros.py`: a script for `/import` that changes nothing until
  the disabled jumps at its end are enabled: interface lists and address
  lists under `fws-`, the rules in `fwshift-forward` (one protocol per rule,
  or a chain of its own), the defaults at its end, NAT through the iptables
  planner into `fwshift-dstnat` and `fwshift-srcnat`, a check at the top that
  stops a second import.
* `fwshift convert --compare` reads RouterOS output back as if its jumps were
  on; `--from routeros`, `--to routeros`, detection of an export.
* `tests/test_routeros.py` (177 tests): a judge that walks RouterOS filter
  chains (jump, return, the default accept, lists, negation) and shares no code
  with the parser; the sample (`routeros_sample.rsc`, written and wrapped at 80
  columns by `tests/tools/make_routeros_sample.py`), 35 golden conversions,
  its audit and matrix.

**What the work made necessary**

* *A return in the middle of a chain.* `return protocol=tcp dst-port=22
  src-address-list=!admins` is the usual RouterOS idiom, and differs from the
  rules below it in three parts at once. Taking it away part by part (the
  admins; not the admins and not TCP; not the admins, TCP and not port 22)
  keeps the rules below exact, at the cost of a model rule per part.
* *The default configuration.* Its forward chain allows everything but what
  comes from WAN and was not translated by destination NAT. Without reading
  `!dstnat` the commonest RouterOS policy could not be converted; with allow
  rules for each port forward ahead of the deny, and a check that nothing
  below blocks what they translate, it is exact.
* *Interfaces an export does not show.* An Ethernet port with default
  settings is in no export unless something names it. A negated interface
  covers the zones the export shows, and says so; one that would leave none
  is not converted rather than dropped.

**Review**

*Round 31* by the independent reviewer, with probe scripts.

| | Finding | Fix |
|---|---|---|
| high | Parser: `connection-nat-state=!dstnat` on a jump or a return was dropped, so a jump for untranslated traffic applied to port forwards too | the property on anything but a deciding rule makes it not converted |
| high | Parser: `#error exporting "/ip/firewall/filter" (timeout)` (RouterOS 7.11+) was read as a comment: no rules, default allow, no word | an error for the firewall, interface and address menus; `ROUTEROS_EXPORT_ERROR` for others |
| medium | Parser: lists filled by raw rules, DHCP servers or PPP profiles were read as static | every `address-list`/`address-lists` that fills a list makes it dynamic |
| medium | Parser: a negated interface on the jump to a chain (and in NAT) was not reported | carried with the condition; `ROUTEROS_NEGATED_INTERFACE` on the rules and NAT rules it reaches |
| medium | Parser: the `!dstnat` expansion ignored later rules with `connection-nat-state=dstnat` | only later `!dstnat` rules are passed over |
| medium | Parser: a verbose export's `connection-state=""` made deny rules not converted | an empty value is an unset property |
| medium | Emitter: `connection-nat-state=dstnat` written in a NAT rule, which RouterOS NAT does not take: the import would stop there | not written; `NAT_AFTER_DNAT` says what the source half then also matches |
| low | Emitter: NAT findings named the planner's placeholder zones (`fwsz0`) | the zones |
| low | Emitter: the check at the top looked at the IPv4 chain only | one check per IP version written |
| low | Parser: `tcp-flags=syn` without a protocol matched every protocol | kept to TCP |
| low | Emitter: NAT comments went through the iptables comment cleaner (quotes, backslashes, 200 characters) | written as they are, escaped |

The fixes were not reviewed again; they have tests (`test_r31_*` in
`test_routeros.py`).

**Verified, and not**

* The tests: 177 in `test_routeros.py`, the suite 4345. The parser against the judge:
  60 random exports (interface lists or interfaces, address lists, negations,
  ports, `port=`, ICMP, states, jumps, conditional returns on several parts),
  400 packets each; the emitter against the judge: 40 random models, both IP
  versions, and the defaults inside and between zones (10); a round trip
  through the script and back (20).
* A mutation check with 45 ways to break the parser and the emitter (5 did not
  apply to the code as it was): 30 caught at first; tests were added for the
  other 10, which catch them all (a negation that leaves no interface the
  export shows, ports with a negated protocol, an ICMP code, an accept of
  invalid packets, a return in `forward` on an interface, a TCP reset on a
  rule that matches more than TCP, the translated port of a port forward, "not
  any", ICMP codes and protocol numbers per IP version in the output).
* **Not verified**: nothing was loaded on a router, and no export of a real
  router was read (the inputs were written by hand to the grammar, and the
  defaults of the default configuration taken from published exports); the
  check at the top of the script, the escaping of `?` and non-ASCII text,
  `dst-port` lists longer than 15 and `icmp-options` with a code range are as
  the documentation and the schemas describe them; the protocol numbers RouterOS
  gives `ipip`, `ipencap` and `encap` are not known, and those names make a rule
  not converted.

### 2026-10-13: version 0.22.0

The zone and conduit model as a gate, and the equivalence check (`TODO.md`,
*Audit and matrix*).

**Built**

* `fwshift conduits`: a zone and conduit model as a JSON file (zones as
  networks or as zones of the policy, conduits with their services, what may
  pass inside a zone, target security levels as documentation), read
  strictly, and a policy checked against it through its zone matrix:
  `NO_CONDUIT`, `CONDUIT_EXCEEDED`, `INSIDE_EXCEEDED`, `NOT_IN_MODEL` (high,
  medium where possible) and `CONDUIT_CLOSED` (low); exit status 3 with
  `--fail-on`. `--draft` writes a model of what the policy allows today.
* `fwshift compare`: every connection whose verdict differs between two
  configurations, of any formats, per pair of zones: opened or closed, for
  certain or possibly, with the rule that decides it in each. `--zone-map`
  (several zones may become one), `--zone-network`, `--app-map`, `--fail-on`.
* `fwshift convert --compare[=FILE]`: the output read back with FWShift's
  parser of the target (eleven targets) and compared with the policy as it
  was read; `COMPARE_EQUIVALENT`, `COMPARE_OPENED`, `COMPARE_CLOSED`,
  `COMPARE_ZONES`, `COMPARE_NOT_READ_BACK` in the report.
* `compare.py`, `conduits.py`; in the matrix, a rule the model does not hold
  exactly is shown wherever its zones reach, whatever its action, and the
  default inside zones the policy does not name is placed; the FortiOS parser
  reads `edit 0` in a numbered table as a new entry (FortiOS scripts, and
  FWShift's own output, use it).
* `tests/test_conduits.py` and `tests/test_compare.py` (202 tests), the
  model of the samples (`zone_model.json`, written by
  `tests/tools/make_zone_model.py`), 6 golden results.

**What the work made necessary**

* *Labels.* A rule for an application, a user or a schedule matches only
  some connections; read from above only, every such rule would be a possible
  difference between a policy and its copy. Comparing per combination of the
  labels the rules use makes them exact; an application on its default ports
  is restricted to those ports by the application map.
* *What cannot be read is alike in both.* A region, a dynamic group, a rule
  the model does not hold exactly: the same in both policies, it decides
  alike, whatever it holds. As labels they keep identical policies equal and
  keep a difference certain only where it holds whatever they are.
* *Zones that become one.* With `--zone-map` several zones of the first may be
  one of the second: the pairs are those of the first, each as the second
  sees it, so that what was between two zones and is now inside one is
  compared.

**Review**

*Round 30* by the independent reviewer, with repro scripts and a fuzzer
against the packet walk of the tests.

| | Finding | Fix |
|---|---|---|
| high | Compare: shared unreadable objects read as empty when their labels were not combined (too many) | read as they are (from above, all; from below, nothing) |
| high | Compare: a dynamic group was "alike" by its filter, whatever the tagged objects; a group with excluded members by its text | the tagged objects are part of the definition; such groups are never alike |
| high | Compare and conduits: a rule the model does not hold exactly was trusted for its extent and its action (FortiOS negation of one IP version, action ipsec) | it may match anything in its zones and allow or block it, unless alike in both; the matrix shows it wherever its zones reach |
| high | Conduits: zones of networks without `policy_zones` left the default inside zones of the policy unchecked | possible findings wherever that default may reach beyond the model |
| medium-high | Compare: zones that become one through `--zone-map` hid what changed between them | the pairs of the first, each as the second sees it |
| medium | Compare: schedules, URL categories and user groups are compared by name, without a word | said in the result and the notes |
| medium | Compare: labels that overlap (a user and a group) made "certain" false | certain only where it holds whatever such labels are |
| medium | Compare: an IPv4-only and an IPv6-only ruleset were "equivalent" (nothing compared) | an error; `convert --compare` says nothing was compared |
| medium | `convert --compare`: ASA output read back has no interfaces or routes; Azure's `outside` had no networks | ASA only with `--zone-network`; the networks by the zones of the source |
| low | Compare: addresses in none of the networks given were not compared | compared as `(elsewhere)` |
| low | Compare: a policy differed possibly from its own copy (any application on its default ports, rules not held exactly) | such rules alike in both are labels |
| low | Conduits: `CONDUIT_CLOSED` for applications where the policy allows everything, and for source ports a conduit cannot say | not closed |
| low | The model file: a key twice, `"networks": []`, `sl_t` 0 against the docstring | errors; 0 to 4 documented |
| low | Text: inside and between of `(other zones)` under one heading; the deciding rule missed for applications on their default ports and for labels | fixed |
| low | Compare grew with combinations times rules squared (100 s for 400 rules and 100 applications) | above a limit the labels are not combined (1.5 s) |
| low | `convert --compare` took its snapshot after the audit's actions | before them |

The fixes were not reviewed again; they have tests (the last sections of
`test_compare.py` and `test_conduits.py`).

**Verified, and not**

* The tests: 202 new tests, the suite 4131. The comparison against a
  walk through labelled packets (an application on or off its default ports,
  users, a dynamic group whose members only the walk knows): 60 random pairs
  of policies in the suite and 1,200 more outside it, every differently
  decided packet in a reported difference, every packet of a certain
  difference decided differently; a policy equal to its copy (20); iptables
  and nftables output read back never differently for certain, and equal
  where the parser reads every rule back exactly (30). The conduit check
  against a walk: 60 random policies and models in the suite and 600 more,
  every packet beyond the model found, no packet through a conduit said to
  be closed.
* A mutation check with 39 ways to break the comparison, the conduit check, the
  matrix and the FortiOS parser: 34 caught at first; one changes nothing (the
  labels of objects that are not combined are empty anyway); tests were added
  for the other four (a rule alike in both that allows, two zones neither
  policy names, an application on ports of its own, the zones the policy does
  not name in a model).
* **Not verified**: the comparison of two real exports of one firewall, and of
  a conversion loaded on a device and exported again; whether the default
  ports of the application map are those of the vendors' applications.

### 2026-10-13: version 0.21.0

The last of four brands planned one release each (`TODO.md`): **Azure network
security groups**, read and written.

**Built**

* `parsers/azure.py`: network security groups as the Azure CLI prints them
  (`az network nsg list` and `show`), as the REST API gives them
  (`properties`, `{"value": [...]}`), from an exported or Bicep-built ARM
  template, and from Resource Graph; with the network interfaces, the virtual
  networks and the service tags, alone or in one array.
* Each group is a zone, everything else `outside`. Inbound and outbound rules
  in the order of their priorities, ending in the default rules (added when the
  export leaves them out). Traffic between two groups as the composition of
  the outbound list of the one and the inbound list of the other. Service tags
  as the addresses of the service tag list, application security groups as the
  addresses of the interfaces that carry them, else dynamic groups.
  `VirtualNetwork` on a group's own side is any of its resources; groups in
  virtual networks that are not peered are not composed.
* Templates: parameters with their default values, variables, `concat`,
  `format`, `resourceId`, `copyIndex`, `if`, `equals` and a few more, with
  index and property access; copy loops of resources and of properties;
  conditions; child rules at the top or nested. What is not worked out
  refuses the template (in a name) or leaves the rule not converted.
* `emitters/azure.py`: an ARM template with a group per zone that has
  networks. Each list in blocks per remote zone, kept to its networks, each
  ending in that zone's default; the zones of the default route last, for their
  IP versions; the default of the source at 4096. A rule as one security rule
  per protocol, IP version and service tag or application security group.
* `--inside-zone` and `--zone-network` apply to Azure; `--target-prefix` and
  `--target-policy` name the groups.
* `tests/test_azure.py` (132 tests), the sample (`azure_sample.json`, written
  by `tests/tools/make_azure_sample.py`), 33 golden conversions, the matrix
  and the audit of the sample.

**What the platform made necessary**

* *Two lists per connection.* Between two groups a connection passes the
  outbound rules of one and the inbound rules of the other. The model has one
  list per pair of zones, so the two are composed into one; that grows with
  the square of the rules, and is capped at 5,000 rules a pair.
* *Rules name addresses, not zones.* Written back, a group's lists are cut
  into blocks per remote zone, so that each zone's default decides all of its
  addresses before the next zone is looked at.
* *Many shapes of one thing.* The CLI, the REST API, templates and Resource
  Graph each give the same groups differently; templates hold expressions,
  which are worked out rather than read as text.

**Sources**

The research notes of this release (read as data, never run): the
`Microsoft.Network` REST API specifications and their examples
(azure-rest-api-specs), the Markdown sources of the Azure documentation
(network security groups, service tags, application security groups, limits,
template functions and export), the network module of the Azure CLI with its
test recordings of real service answers, the Resource Graph extension of the
CLI, and the Terraform azurerm provider as corroboration. No subscription was
used: the sample is written by hand from those.

**Review**

*Round 29* by the independent reviewer, with repro scripts and fuzzers.

| | Finding | Fix |
|---|---|---|
| high | Emitter: with a zone of the default route of one IP version only, the block for addresses of no zone was left out for both versions; a deny rule was lost for the other version | that block is kept to the versions no zone of the default route holds; a zone with networks of the other version gets a block for them too |
| high | Parser: a priority that is not a whole number (an expression, text, NaN, `true`, 100.9) was sorted last without a word | the rule is not converted; one outside 100 to 4096 too |
| high | Parser: nested child rules, copy loops, rules given by a parameter, Bicep's `format` and conditions in templates were lost or misread | worked out; what is not refuses the template or leaves the rule not converted (`AZURE_TEMPLATE_CONDITION`) |
| high | Emitter: a rule name cut to 76 characters and numbered looped for ever from the thousandth | the name is cut to leave room for the number; a counter per name |
| medium | Emitter: a group whose own zone holds a default route of one version ended in the default between zones; `intrazone_allow = False` was read as the policy's default | the default inside the zone for that version; False is deny |
| medium | `*` may cover more than TCP, UDP and ICMP (the default DenyAll rules use it) | an allow rule names the three; the parser raises `AZURE_ANY_PROTOCOL` to review when an allow rule for ESP or AH follows a deny rule `*` |
| medium | `VirtualNetwork` between groups in virtual networks that are not peered was read as reaching each other | not composed (`AZURE_NOT_PEERED`); reported when the export does not say (`AZURE_PEERING_UNKNOWN`) |
| medium | Members of an application security group from part of the interfaces were taken as all of them | `AZURE_ASG_MEMBERS`, review when deny rules name them |
| medium-low | Resource Graph answers of the REST API: `totalRecords`, `$skipToken`, `resultTruncated` not looked at; the table format ignored | looked at; the table format refused |
| medium-low | A group named only by its subnet (in the virtual network) or by its interface had no networks and no chain finding | both associations read |
| low | The emitter refused a group only above 3,990 rules per direction; Azure allows 2,000 in all and 100 application security groups | those limits |
| low | An application security group from a template was written back as `/Microsoft.Network/...`, not a resource id | written as `resourceId(...)` in the resource group deployed to |
| low | The composition grows with the square of groups and rules | measured (20 groups of 60 rules: 38,520 rules in 5 s), said in the manual's limits and in `TODO.md` |

The fixes were not reviewed again; they have tests (the last section of
`test_azure.py`).

**Verified, and not**

* The tests: `tests/test_azure.py` holds 132 tests, the suite 3929. A
  judge of groups as Azure decides them (the outbound list of the source's
  group, the inbound list of the destination's, priorities, defaults, service
  tags, application security groups), sharing no code with the parser: random
  groups in exact and loose form, more than 10,000 connections each; a judge of
  the emitted template: 40 random models exactly (but for what the report says
  is left out), 20 with zones inside, 20 with zones without networks (never
  more), 24 with zones of the default route of one IP version and random
  defaults; the sample converted to Azure and judged again.
* A mutation check with 40 ways to break the parser and the emitter: 37
  caught at first (one by hanging the test run); tests were added for the
  other three (the order of the export used for what is said of the rules, a
  deny rule that cannot be cut kept to the allow rule's side, a blocking rule
  of a zone without networks kept to that zone).
* **Not verified**: nothing was read from or deployed to an Azure
  subscription. Whether `*` matches ESP, AH and other protocols, what
  `VirtualNetwork` holds across peerings and gateways, whether Azure accepts
  every rule as written (names, descriptions, address limits), and how the
  CLI prints protocol names are taken from the specifications, the recordings
  and the documentation.

### 2026-10-13: version 0.20.0

The third of four brands planned one release each (`TODO.md`): **AWS EC2
security groups**, with the network ACLs where they decide, read and written.

**Built**

* `parsers/aws.py`: the JSON of the AWS CLI for one VPC, the answers alone or
  in one array, each told by its top-level key: `describe-security-groups`
  (required), `describe-network-interfaces`, `describe-vpcs`,
  `describe-subnets`, `describe-network-acls`, the managed prefix lists and
  their entries, `describe-security-group-rules`.
* A group is the private addresses of the interfaces that carry it; without
  the interfaces a dynamic group no target writes. Inbound rules allow their
  sources to reach the members; outbound rules are for the destinations
  outside the VPC. Where a member's outbound rules do not allow everything
  inside, rules for each outbound rule of its groups and inbound rule of the
  destination's, and a rule that blocks the rest. Public and Elastic IPs of
  instances as static NAT. Network ACLs as blocking rules between subnets, in
  rule-number order; replies through a stateless ACL, routed paths and
  traffic to the VPC's own public addresses are reported.
* `regions.py`: boxes of connections (IP version, sources, destinations, the
  service sets of the audit) with intersection and subtraction, and service
  sets back to entries, positive or negated.
* `emitters/aws.py`: a POSIX shell script of AWS CLI calls (print, `--dry-run`
  and real modes) that creates new groups and their rules. Each allow rule
  without the deny rules above it, each piece as an inbound rule at the
  destination and an outbound rule at the source, every address in one group
  per IP version; `--inside-zone` (and an AWS source's VPC) keeps the groups
  to the VPC.
* `--inside-zone`, a new option of `convert`.
* `tests/test_aws.py` (104 tests), the sample (`aws_sample.json`, written by
  `tests/tools/make_aws_sample.py`), 31 golden conversions, the matrix and the
  audit of the sample.

**What the platform made necessary**

* *Allow only.* A first-match policy with blocking rules has to be turned into
  what each allow rule really allows; the matrix already did that for its
  cells, the emitter now does it for every rule.
* *Two ends, one side each.* A rule of a group names the other end only.
  Writing every piece at both ends makes the outcome exact whichever addresses
  turn out to be interfaces.
* *Members are interfaces.* Without `describe-network-interfaces` a group
  stands for nothing anyone can write. Interfaces of NAT gateways and load
  balancers carry no groups, and their public addresses publish nothing.

**Sources**

The research notes of this release (read as data, never run): the EC2 service
model of botocore 1.43 (`service-2.json`, paginators, waiters), the AWS CLI
command reference, the VPC and EC2 user guides (security groups, rules,
default groups, quotas, network ACLs, prefix lists, security group VPC
associations, connection tracking), the Transit Gateway guide, and the
Terraform AWS provider as corroboration. No account was used: the sample is
written by hand from that model.

**Review**

*Round 28* by the independent reviewer, with repro scripts and a stand-in for
the AWS CLI.

| | Finding | Fix |
|---|---|---|
| high | Parser: traffic from inside to a public address of the VPC was read as traffic to the private address; on AWS it leaves through the internet gateway, with public addresses at both ends | outbound rules keep the public addresses; the rest is reported (`AWS_HAIRPIN`) |
| high | Emitter: outbound rules were widened to the public addresses NAT maps inside, where an inbound rule for an outside range then let the source's public address in | widened to the private inside only |
| high | Emitter: an intrazone blocking rule was kept to its destination zones, which the model does not look at; it blocked less | the source zones on both sides |
| medium | Groups are cut by address, AWS applies them per interface | said in `AWS_ATTACH`, the manual and the script |
| medium | Script: when the new group's outbound rules were not listed, the default allow-all rule stayed, silently | both default rules revoked by their permissions, and a group that still has outbound rules stops the script |
| medium | Replies through a stateless ACL: ICMP echo replies and other protocols were not checked | checked with TCP and UDP |
| medium | ACLs of subnets traffic is routed through (a NAT gateway's) were ignored; a NAT gateway's public address became a static NAT | `AWS_ROUTED_THROUGH`; only instance interfaces publish |
| medium | `1e400`, `Infinity`: `OverflowError` | `ParseError`, or the value cannot be read |
| low | ACL entries without their port range or ICMP type, TCP and UDP rules without ports, were read as all | not converted |
| low | IPv6 ACL rules were lost for a subnet whose answer lists no IPv6 block | the members' IPv6 addresses stand for it |
| low | The script checked each name just before creating that group | all names first |
| low | A CIDR without a prefix length was used in the pairs; groups whose members are unknown were left out of them silently | refused; said |

The fixes were not reviewed again; they have tests (the last section of
`test_aws.py`).

**Verified, and not**

* The tests: `tests/test_aws.py` holds 104 tests, the suite 3762. A
  judge of a VPC (groups of interfaces, outbound and inbound rules, prefix
  lists, network ACLs of both subnets, public addresses), sharing no code with
  the parser: 120 random VPCs, more than 10000 connections judged; a judge of
  the emitted script: 40 random models exactly (but for what the report says
  is left out), 20 with zones without networks, source ports and rule types
  (never more), 20 with zones inside the VPC; the sample converted to AWS and
  judged again. The script itself runs in its three modes against a stand-in
  for the AWS CLI.
* A mutation check with 27 ways to break the parser, the emitter and
  `regions.py`: 24 caught at first; a test for one more (ICMP type and code
  swapped) was added; the other two change nothing that can be reached (a
  check the subtraction of the VPC makes again, and source ports the emitter
  never leaves in a piece).
* **Not verified**: nothing was read from or sent to an AWS account. Whether
  `--dry-run` checks more than permissions, which addresses of an interface a
  group reference covers (secondary, IPv6, delegated prefixes), whether
  describe answers echo protocol numbers or names, and whether AWS accepts
  every call as written are taken from the service model and the
  documentation.

### 2026-10-13: version 0.19.0

The second of four brands planned one release each (`TODO.md`): **VMware NSX**,
its distributed firewall, read and written.

**Built**

* `parsers/nsx.py`: the JSON of the Policy API, either the hierarchical
  answer of `GET /policy/api/v1/infra` (Child wrappers, domains, rules inline
  or as children) or the list answers of groups, services, security policies
  and rules, alone or several in one array; the communication maps of NSX-T
  2.4 as well.
* Policies in the order NSX runs them: category (Ethernet left out and
  counted, Emergency, Infrastructure, Environment, Application), sequence
  number (or the old `precedence`), the default policy last in its category;
  rules by sequence number. `JUMP_TO_APPLICATION` skips the rest of
  Environment, across policies; a jump with conditions or a scope flags what
  it may skip. The default layer-3 rule is the default of the model.
* Groups: addresses, networks and ranges, nested groups by path, segments as
  their subnets, AND and OR of expressions; groups NSX fills itself (tags,
  names, virtual machines) as dynamic groups that keep their expression.
  Services: L4 port sets, ICMP, IP protocols, IGMP, ALGs as their ports,
  nested services, and the system services by their id.
* What decides in NSX and has no place in the model is read as far as it
  decides: applied-to (both ends covered, one end, none), direction, IP
  version (a rule per version, or a literal of that version), profiles,
  stateless policies, connectivity preference. Missing fields are never any.
* `emitters/nsx.py`: the body of one hierarchical `PATCH`: services (at most
  15 ports per entry), groups per IP version, one security policy of category
  Application named by `--target-policy`, rules numbered in the order of the
  model; zones as the networks of `--zone-network`; a last rule that denies
  when the source does; NSX to NSX, dynamic groups, applied-to and IP version
  written back. NAT is not written (it belongs on the gateway); the rules name
  the translated addresses.
* `tests/test_nsx.py` (64 tests), the sample (`nsx_sample.json`, written by
  `tests/tools/make_nsx_sample.py`), 60 golden conversions, the matrix and the
  audit of the sample.

**What the platform made necessary**

* *Two ends.* NSX checks a connection where it leaves and where it arrives.
  Rules that apply to one workload, or to one direction, do not decide alone;
  they are read only where both ends agree, and flagged otherwise.
* *Names are not identifiers.* Display names repeat, and can be `any` or look
  like an address; ids are what rules refer to, by path. Names are made unique
  and renamed where the model would read them as a keyword or an address.
* *System objects are shared.* The system services must be referred to, not
  written again: a body that names `HTTP` would change it for every policy.

**Sources**

The research notes of this release (read as data, never run or imported):
the schema of VMware's Policy API Python SDK 4.2 (`model_client.py`, parsed
with `ast`), the Terraform provider for NSX-T and VMware's Ansible modules,
the OpenStack NSX library, and the API reference read through summaries. No
answer of a real manager was available: the sample is written by hand from
that schema.

**Review**

*Round 27* by the independent reviewer, with repro scripts of its own.

| | Finding | Fix |
|---|---|---|
| critical | A group or service named `any` became "any"; a group named like an address took over that address in other rules | renamed (`RENAMED`), as the other parsers do |
| high | `JUMP_TO_APPLICATION` skipped only the rest of its own policy; a jump with conditions or a rule scope was read as unconditional | the rest of Environment is skipped across policies; a conditional jump flags what it may skip |
| high | Emitter: an FQDN inside a nested group was left out of the group, and the rule stayed enabled | the rule is written disabled (`FQDN_NOT_SUPPORTED`) |
| high | A rule for one IP version between dynamic groups lost the version; NSX to NSX it allowed the other version | the version is kept and written back as `ip_protocol` |
| high | An allow rule applied to one end only was converted unflagged | `APPLIED_TO_ONE_END`; applied-to written back NSX to NSX |
| medium | Missing `action`, sources, destinations or services read as allow any; rules without a type or an id lost | never any: the rule is unsupported; rules without a type are rules; de-duplication only by id or path |
| medium | Several default rules: the last one won; a default rule in an ordinary policy became the default | defaults only in default policies, the global one preferred, a note when there are several |
| medium | Malformed input crashed with other errors than `ParseError` | wrapped, with type checks |
| medium | Emitter: dynamic groups kept paths to groups by their old ids | rewritten to the ids written |
| medium | Generated services took the ids of system services | system ids reserved |
| medium | `precedence` of communication maps ignored | read |
| low | Missing or misleading notes (equal sequence numbers in a policy, gateway rules, a non-numeric ICMP type read as 0, `--zone-network` help) | added, corrected, the ICMP type unsupported |
| low | Applied-to joined by commas; a group loop check that never fired; `NSX_LOAD` without `--target-prefix` | a separator no name holds; the check fixed; the note names the option |

The fixes were not reviewed again; they have tests (the last section of
`test_nsx.py`). One question of the reviewer was settled in the parser: the
default policy comes last in its category whatever its sequence number.

**Verified, and not**

* The tests: `tests/test_nsx.py` holds 64 tests, the suite 3625. A judge of
  Policy API JSON (categories, sequence numbers, jump, default rule, groups,
  services), sharing no code with the parser: 150 random policies against the
  parsed model; 40 random models emitted and judged with zones as networks;
  a round trip NSX to NSX that keeps every decision.
* A mutation check with 23 ways to break the parser and the emitter: 22
  caught at first; a test for the last (the place of the default policy) was
  added, and catches it.
* **Not verified**: nothing has been sent to an NSX Manager, nor read from
  one. Whether a manager accepts the body as written (ids, `profiles`, the
  entries of a service), the exact answer of a full export, which system
  services exist beyond the common ones, and whether a segment in a group
  means its subnet or only its workloads are taken from the schema and the
  documentation.

### 2026-10-13: version 0.18.0

The first of four brands planned one release each (`TODO.md`): **nftables**,
read and written.

**Built**

* `parsers/nftables.py`: `nft list ruleset` text and `nft -j list ruleset`
  JSON, both read into one structure (tables, chains, sets and maps, rules of
  matches and statements), so the two listings give the same model. The text
  reader also takes an input file for `nft -f` with tables in braces
  (`define`, `flush ruleset`, `delete table`, a table in several blocks).
* What a rule matches is a condition of exact sets (IP versions, interfaces,
  address intervals per side, protocols, port ranges, ICMP types and codes,
  connection states), so jumps, sets and maps combine by intersection. Named
  sets of addresses become address groups; the way a side was written (a
  set, a negation) is kept to show it where the intersection leaves it so.
* Chains are flattened: jump, goto (to the policy at the base chain, to the
  caller below it), return (the policy at the base chain; below it, exact
  where one condition can say what is left), verdict maps, concatenations and
  NAT maps as one rule per element, anonymous chains.
* Every base chain at the forward hook of the ip, ip6 and inet tables, in the
  order of its priority, combined into one list of first-match rules: a rule
  that accepts is followed by the rules of the next chain under it, a policy
  that accepts by the next chain. IPv4 and IPv6 are walked apart where they
  meet different chains; a version without a chain is not filtered
  (`NO_IPV6_CHAIN`, the policy for the other version, as for iptables).
* The stateful reading of iptables (an accept of every established packet is
  left out, `STATELESS_RULESET`, `DROP_BEFORE_ESTABLISHED`, logging from log
  rules, `LOG_EVERY_PACKET`), NAT from the nat chains at prerouting and
  postrouting as iptables NAT is read, `transform.rewrite_destinations`.
* `emitters/nftables.py`: one table, `inet fwshift`, created, deleted and
  written again in one file (`nft -f` loads it as one transaction). Anonymous
  sets for lists, one line per IP version and protocol, a chain per negated
  service, `log` statements for rules that log the start of a connection, NAT
  through the iptables emitter's planner, translated into nft syntax.
* `fwshift usage` for an nftables policy: a `log` statement writes the kernel
  lines a `LOG` rule does, so the iptables reader reads them; `log group`
  (nflog) is evidence of nothing, as `NFLOG` is.
* `tests/test_nftables.py` (75 tests), the sample (`nftables_sample.nft` and
  `.json`, written by nft itself through `tests/tools/make_nftables_sample.py`),
  27 golden conversions, the matrix and the audit of the sample, and
  `tests/tools/nft_kernel_check.py`.

**What the platform made necessary**

* *Every base chain decides.* Tables are only a way to group chains: every
  base chain at a hook sees every packet, an accept is not final, a drop is.
  A table read alone is not the policy; neither is a converted table loaded
  alone, which is why the emitter's `NFT_LOAD` note names the other tables.
* *A listing is not an input file.* nft prints a range as a prefix where it
  is aligned (`snat to 198.51.100.20/30`), a negated set in braces, flags
  joined by commas, set elements wrapped over lines, and the statements it
  cannot translate as `xt` (JSON always, text where libxtables has no
  translation).
* *Nothing read is ever a guess.* A word the reader cannot place makes the
  rule unsupported; a verdict word is never read as a value, and a rule
  without a verdict that could not be read in full is a drop that is not
  enforced.

**Sources**

The research notes of this release (from the upstream nftables release
tarballs 0.9.3, 1.0.2, 1.0.9, 1.1.1 and 1.1.6, iptables 1.8.11 and the Debian
packaging, read and not run): nft(8), libnftables-json(5), the `tests/py` and
`tests/shell` dumps of nft's own test suite, `src/rule.c` (how a ruleset is
printed), `src/json.c`, `src/xt.c`. Checked against nft 1.0.9 here: every
listing the tests use was printed by it.

**Review**

*Round 26* by the independent reviewer, with repro scripts of its own and the
kernel (probes at the output hook in a network namespace).

| | Finding | Fix |
|---|---|---|
| critical | A conditional goto in a chain below the base chain went on with the rest of that chain for packets that had gone back to the caller; an unconditional goto in a chain reached by a goto from the base chain lost the policy at its end. Both allowed what the kernel drops | the packets of a goto are taken out of what the rest of the chain sees (or that rest is marked); the end of the goto meets the policy |
| high | Text listings: `log flags tcp sequence,options`, `quota name`, TCP and IP options, `exthdr`, `sctp chunk`, `meter`, `osf`: a word out of step took the verdict as a value, and the drop rule was gone, unflagged | a verdict word is never a value; those statements are read; a rule without a verdict that could not be read in full is an unknown verdict |
| high | JSON: a jump to an anonymous chain (written as text, no JSON form) lost the rule | an unknown verdict |
| medium | An accept of established packets with more matches (an interface) was left out as if it accepted every established packet | a rule of its own, disabled; only a plain one makes the ruleset stateful |
| medium | Dormant tables were converted (a NAT rule that publishes nothing became live) | skipped, `TABLE_DORMANT` |
| medium | `$` in a log prefix: nft expands it, and the file does not load | replaced |
| low | `nft -n` listings: numeric connection states were not read | read |
| low | `IPTABLES_NFT` said `xt` always shows; in text nft translates most extensions | reworded: the two listings can differ |

The fixes were not reviewed again; they have tests (the last section of
`test_nftables.py`), and the reviewer's chain generator is in the suite
(`deep_ruleset`).

**Verified, and not**

* The tests: `tests/test_nftables.py` holds 75 tests, the suite 3530.
  A reference that walks a ruleset as the kernel does (every base chain, jump,
  goto, return, maps, sets), sharing no code with the parser's reading of a
  match: 120 random rulesets of two tables and 800 of chains three deep
  against the model; random models emitted and walked by the reference; with
  nft present, 40 random rulesets loaded into the kernel and listed back as
  text and JSON (the same model), and every emitted file and golden checked
  with `nft -c`.
* **Real packets** (`nft_kernel_check.py`, 40 seeds): 111 rulesets, 20216
  packets, 8764 of them forwarded, on kernel 6.18 with nft 1.0.9: the kernel
  and the model agreed on every packet, emitted rulesets and parsed ones.
* A mutation check with 21 ways to break the parser and the emitter: 19
  caught at first; tests for the other two (a negated connection state, the
  IP version an ICMP match implies) were added, and catch them.
* **Not verified**: NAT and IPv6 forwarding through the kernel (loaded, not
  sent through); nft versions other than 1.0.9 (their output formats are
  taken from their sources); listings of real hosts with firewalld, Docker or
  libvirt tables.

### 2026-10-13: version 0.17.0

The fifth and last planned release of *rule usage* (`docs/RULE_USAGE.md`):
narrower rules proposed from what the logs show went through a rule.

**Built**

* `narrow.py`: the narrower cells of an allow rule. Addresses as the logs give
  them (or the networks a store keeps beyond its limit), grouped into /24 and
  /16 (IPv6 /64 and /48) while there are more than 16, and cut back to the
  cell; services as the protocols, ports and ICMP types used, at most 16. A
  cell is narrowed only where the audit knows all it holds (`_Match` over and
  under sets equal, not negated), every connection said what it used there,
  and what they used lies inside it. `build()` makes a policy of the proposed
  rules alone (`<rule>-narrowed`), with objects named by what they hold, or
  the policy's own object that holds just that.
* `usage.py`: what the connections of each rule used, per cell
  (`LogUsage.seen`, certain and possible connections, at most 4096 values),
  and the cells a connection left unknown (`LogUsage.blind`: no address or
  port, a FortiOS destination NAT).
* Audit: `WIDER_THAN_TRAFFIC` (low; off, accept, report) for a used allow rule
  whose logs prove its use, when a cell keeps at most `wider_than_traffic`
  percent (a new threshold, 10) of what it holds; the finding carries the
  proposal (`proposal` in the JSON). No proposal for a blocking rule, a rule
  read approximately, a part of a split rule, or the destinations of a rule
  with a destination NAT.
* `fwshift usage --propose FILE [--propose-to FORMAT]`: the proposed rules as
  the neutral model (JSON, the default), or through an emitter, with its
  conversion report next to it and the rules where the policy's are (vsys or
  device group, VDOM, layer). The report lists the narrower rules.
* The PAN-OS emitter keeps a PAN-OS rule's log forwarding profile.
* Manual: section 15, *Narrower rules*; the check and the threshold in
  section 13; the options in section 5.
* `docs/guide.html`: a field guide on one page, every feature with commands
  and output of the samples, and per brand what to export, how to load the
  result and what to watch for, with a filter over those lists. Its facts come
  from the manual; the version test checks that it names this version.

**What the platform made necessary**

* *Never wider.* Every network of a proposal is cut back to the rule's own
  set; where the logs show what the model cannot place, nothing is proposed.
* *A proposal is a review, not a change.* The emitters write whole
  policies: a table to restore, a layer with a cleanup rule, access groups.
  A conversion of the narrowed rules alone still carries that around them,
  so it is written for its rules to be taken from, with its report, and the
  default is the neutral model.
* *New rules, not edits.* `set` commands add members to a rule of the same
  name (PAN-OS, Juniper): a narrower rule has a name of its own.

**Sources**

None outside the project: the audit's sets (`_Reader`) and the emitters.

**Review**

*Round 25* by the independent reviewer, with repro scripts of its own. The
narrowing itself held (20,000 fuzzed cells never wider, never short); what it
found was in what `--propose` wrote:

| | Finding | Fix |
|---|---|---|
| critical | A Check Point proposal script puts its rules at the top of the layer with a cleanup Drop below them: installed, it shuts off the rulebase | JSON by default; a vendor format is written as a conversion to take the rules from, never to load, said in the report and the manual, with its conversion report |
| high | FortiOS: a narrowed policy loses its NAT and profiles; a virtual IP is written as an address | in the conversion report now written next to it; the manual no longer says everything is kept |
| high | iptables: an unnarrowed destination kept the pre-NAT address of a NAT rule the proposal does not hold: wider than the rule | dropped |
| medium-high | The conversion report of the proposal was thrown away (rules written disabled, approximated) | written next to it |
| medium | Proposal files carry whole-policy scaffolding (tables, access groups, deny rules) | as the first finding |
| medium | PAN-OS: the log forwarding profile of a narrowed rule was dropped | the emitter writes it |
| medium | No target scope for the proposal | the policy's vsys or device group, VDOM, layer |
| low | Objects that hold the same address under another name were created again; FortiOS destinations were never narrowed; the message counted possible connections as carried | reused; narrowed unless they name a virtual IP; worded apart |

The fixes were not reviewed again; they have tests (the last section of
`test_narrow.py`).

**Verified, and not**

* The tests: `tests/test_narrow.py` holds 81 tests, the suite 3426.
  Narrowed addresses against random cells (40 seeds): never outside the cell,
  holding every address seen, at most 16 networks; narrowed services against
  random service sets: inside the set, or nothing; the iptables proposals of
  the sample written as iptables rules and read back: each inside its rule.
  A mutation check with 16 ways to break the narrowing, the check, the
  collection of what was used and the writing: 13 caught at first; the
  tests for the other three (more services than a proposal holds, a negated
  source, a connection without its address) were added, and catch them.
* **No proposal was loaded on a device.** A proposal written for a target
  other than iptables was not read back; what the logs did not see in the
  window (a quarterly job) is not in a proposal.

### 2026-10-13: version 0.16.0

The fourth release of *rule usage* (`docs/RULE_USAGE.md`): the traffic logs of
PAN-OS and FortiOS, which name the rule the firewall chose.

**Built**

* `logreaders/panos.py`: TRAFFIC logs in the syslog format of PAN-OS (BSD or
  IETF header, or none; 8.1 and later, fields read by their position) and the
  CSV export, also with every field in quotes. A line names the rule by UUID
  (9.0 and later) and name; the gateway is the serial number (what Panorama's
  targets name). `end`, `drop` and `deny` are connections (the repeat count is
  the number of sessions); a `start` whose end is in the file is counted once,
  a start naming another rule than its end (the application changed) counts
  for that rule too, a start without an end and a line with the flag of a
  temporary match (`0x2000`) are possible. Times from the high resolution
  timestamp (with its zone), else local time with `--log-offset`.
* `logreaders/fortios.py`: traffic logs in FortiOS's `key=value` format, also
  behind a syslog header and with a FortiAnalyzer's `logver=` in front.
  Forward logs of firewall policies; the action says whether the policy let
  the session through; the start of a session whose end is logged, interim
  statistics, the FortiGate's own traffic and other kinds of policy are
  counted apart, each with its reason. Times from `eventtime` (seconds,
  milliseconds or nanoseconds), else `date`, `time` and `tz`, else
  `--log-offset`. The destination after destination NAT (`tranip`,
  `tranport`) where it is logged.
* `usage.py`: rules found by their identifiers (`_Ids`: UUID first, then name
  or policy ID, never a rule whose UUID says otherwise); the virtual system or
  VDOM of the policy; PAN-OS default rules and FortiOS policy 0 as the
  default; lines of hosts not given with `--gateway` left out, unless the rule
  is installed on them; a name or policy ID in the logs of several firewalls
  certain only for a firewall the policy is on; coverage per virtual system
  and VDOM; times before 2000 or ahead of now are doubts. Evidence: a PAN-OS
  rule without a log forwarding profile, and a FortiOS policy that does not
  log all its sessions, prove nothing.
* `hits.py`: the creation and change times of PAN-OS rules in the answer of
  `show rule-hit-count` become `Rule.changed` (the latest of several
  firewalls).
* The FortiOS parser no longer takes `logtraffic-start enable` with
  `logtraffic disable` for logging.
* Samples: `panos_logged.xml` (the PAN-OS sample with log forwarding
  profiles) with `panos_logged.log`, and `fortios_sample.log`, 90 days each,
  written by `tests/tools/make_panos_logs.py` and `make_fortios_logs.py`;
  their reports as golden files.

**What the platform made necessary**

* *A name is not an identity.* Rule names and policy IDs repeat across
  firewalls and revisions; UUIDs do not (Panorama gives a pushed rule the
  same UUID everywhere). The weaker identifier only counts where the
  stronger one does not contradict it and the firewall is one the policy is on.
* *Logged means sent.* PAN-OS logs stay on the firewall without a log
  forwarding profile; FortiOS logs only some sessions by default.
* *One session, two lines, two rules.* A start and an end are one
  connection; a new lookup after App-ID can name another rule, which matched
  the session too.
* *Parts of a firewall.* A virtual system or a VDOM may send its logs
  elsewhere: its days are its own.

**Sources**

Palo Alto Networks' traffic log field lists (9.1, 10.0, 10.1 to 11.x), the
syslog server profile and Panorama rule-UUID pages, and LIVE community
threads; Fortinet's FortiOS log message reference (6.2 to 7.4), CLI references
and community tips; the parsers and test fixtures of Elastic (`panw`,
`fortinet_fortigate`), Splunk Connect for Syslog, Wazuh and Microsoft
Sentinel, read and never run. Fixture lines with real public addresses were
not copied.

**Review**

*Round 24* by the independent reviewer, with repro scripts of its own:

| | Finding | Fix |
|---|---|---|
| high | With `--gateway`, the lines of a Panorama target not given were left out, while its days still counted: a rule it used was called unused | a line of a target of the rule it names counts |
| high | A PAN-OS rule without a log forwarding profile sends no logs to syslog, and could be called unused | proves nothing; the PAN-OS log sample has its own configuration with profiles |
| high | FortiOS port forwarding: the policy names the mapped port, the log the original one: a false `UNUSED_RULE_SERVICE` | `tranport` read; a service of either port counts |
| high | FortiOS central NAT: the policy names the mapped address, the log the external one: a false `UNUSED_RULE_OBJECT` | `tranip` read; a member of either address counts |
| medium | A FortiOS session ID taken again swallowed a start of another session | a start and an end are one only when policy, addresses, protocol and port agree |
| medium | Logs that name only rules the policy does not have still counted as this policy's logs | only lines naming a rule, a disabled rule or the default of the policy do |
| medium | The days logged by another virtual system or VDOM counted for this one | coverage per vsys and VDOM |
| low | A time with a year like 0268 or 9999 broke the window of the store | a doubt |
| low | Of two hit-counter answers, the first change time was kept | the latest |
| low | A FortiOS line without `date=` was no FortiOS line; `logtraffic-start enable` with `logtraffic disable` counted as logging; a PAN-OS protocol number was not read | read; not logging; read |

The fixes were not reviewed again; they have tests (the last section of
`test_traffic_logs.py`).

**Verified, and not**

* The tests: `tests/test_traffic_logs.py` holds 42 tests, the suite 3345.
  Attribution by identifiers against a reference on 20 random policies of
  each vendor; the readers on the line shapes of the documentation and the
  published fixtures (with documentation addresses). A mutation check with 22
  ways to break the readers, the attribution, the coverage and the evidence:
  all caught.
* **No log of a real firewall was read.** Which rule a PAN-OS end log names
  after an application change, the meaning of the defaults of
  `intrazone-default` and `interzone-default` for logging, and the CSV
  export of PAN-OS 10.x and later are not confirmed by Palo Alto Networks'
  documentation; FortiOS `csv` and CEF output, and the IPv6 policies of
  FortiOS before 6.4, are not read.

### 2026-10-12: version 0.15.0

The third release of *rule usage* (`docs/RULE_USAGE.md`): attribution where
a log names no rule, by matching the connection against the rules of the
policy, counted as certain or possible; and the first logs that need it, the
lines of iptables `LOG` rules.

**Built**

* `simulate.py`: first match over the enabled rules, each read as the audit
  reads it (`audit._Reader.match`: the sets a rule surely and might match). A
  connection is certain for the first rule it might meet when that rule surely
  matches it; possible for every rule from the first it only might match down
  to the first that surely matches it; the default of the policy when none
  might. A rule with users, applications, URL categories or a schedule, one
  the parser read approximately, and a zone, port or address the log does not
  give are never sure. Where the log has a verdict, rules of the other action
  are passed over. An address may be a network (what a store keeps beyond its
  cap). Memoized per point.
* `logreaders/iptables.py`: the kernel lines of `LOG` rules as syslog (old
  form, with `--log-year` and `--log-offset`) or the journal (ISO times) keeps
  them; the interfaces are the zones, the destination port or ICMP type the
  port. Not counted, each with its reason: the firewall's own packets (`IN=`
  or `OUT=` empty), TCP packets that open no connection, `TRACE` and
  `ebtables` lines. Doubts on their gateway and day: lines that say lines were
  lost, lines of a `LOG` rule that cannot be read, times without a year.
* `usage.py`: records without a rule are simulated; `LogUsage.simulated`,
  `possible` and `method`; a connection certainly given to an allow rule is an
  accepted one for the evidence. Check Point lines whose uids cannot be put on
  their rows, and access-role parts of which several fit, are possible now.
  `--gateway` filters the hosts of target-less rules; without it, the
  simulated connections of a store of several hosts are possible only, as are
  those of other protocols than TCP when the logs may hold packets of open
  connections. Reports: possible counts and why.
* Audit: a rule with possible connections only gets `NO_USAGE_EVIDENCE`,
  never `UNUSED_RULE`; `--unchanged-since` (and `unchanged_since` in the
  configuration) for a rule whose export does not say when it changed.
* iptables parser: a `LOG` rule that matches every packet, or every new
  connection, logs the rules below it, the latter only where only new
  connections reach them; a rule logged through `NFLOG` or `ULOG` only says so
  (`source_ids["iptables.log_target"]`); a note `LOG_EVERY_PACKET` where a
  `LOG` rule logs packets of open connections.
* Command options `--log-year`, `--log-offset`, `--unchanged-since`.
* Sample: `iptables_logged.rules` and `iptables_logged.log` (90 days of one
  host, written by `tests/tools/make_iptables_logs.py`), its report as a
  golden file.
* Also in this release, a patch from a separate session (a review of the
  conversion of a faulty Check Point configuration): JSON without a
  `rulebase` (object listings alone, or a hand-written policy with
  `access-layers`, `sections` and `rules` that name their objects) is refused
  with `no rulebase found`, its top-level keys and the `mgmt_cli` call for a
  real export, instead of being read as a policy of no rules; `IMPLIED_RULES`
  no longer says a layer was read when none was (a NAT-only export). A
  fixture, `checkpoint_perimeter.json`: 23 rules and 5 NAT rules in the shape
  of the Management API, with sections, a network feed and updatable objects;
  its `No NAT for VPN` is shadowed by `Hide NAT Internal`. Three tests in
  `test_checkpoint.py`. Read in full before it was applied; its addresses are
  from RFC 1918 and RFC 5737 only.

**What the platform made necessary**

* *No rule in the line.* The policy decides; what it cannot decide (a
  `-m limit` rule, a negation it could not read) is possible for every rule it
  may be, and no rule with possible connections only is called unused.
* *Post-NAT addresses.* `LOG` in `FORWARD` sees the destination after DNAT,
  which is what the audit's matches use for a platform that looks rules up
  after NAT; the pre-NAT objects the parser adds are not counted.
* *No age.* iptables never says when a rule changed: without
  `--unchanged-since` nothing is called unused.
* *Packets, not connections.* A `LOG` rule logs packets; which ones reach it
  depends on the rules above it. That decides both whether a rule's
  connections were logged and whether a line may be a packet of a connection
  already open.

**Sources**

The line format as the kernel's `LOG` target writes it (`nf_log_syslog.c`:
`IN= OUT=`, `MAC=`, `SRC= DST=`, `PROTO=`, the ports or ICMP type, the TCP
flags ending at `URGP=`, a quoted packet in brackets), the iptables and
iptables-extensions man pages (`LOG`, `NFLOG`, `conntrack`), and the
timestamp forms and lost-line messages of rsyslog and systemd-journald, as
known; no source was fetched for this release, and no line was taken from a
running kernel (the kernel check of 0.4 forwards packets, it does not log
them).

**Review**

*Round 23* by the independent reviewer, with repro scripts of its own:

| | Finding | Fix |
|---|---|---|
| high | A line without a port reached the simulator as port -1, which no rule might match: it went to the default, and the rules of its protocol could be called unused | -1 is unknown, as None; the oracle now gives both |
| high | A `LOG` of new connections at the top made every rule below it logged, also rules that only packets of other states reach (`RELATED`, a stateless ruleset): false `UNUSED_RULE` | logged only for a rule of new connections, or any rule once established and related packets are accepted above it |
| medium | `UDPLITE` lines were read as UDP: certain for a UDP rule, and the udplite rule called unused | protocol 136 kept |
| medium | `NFLOG` and `ULOG` counted as logging, but only kernel lines are read | the rule says it logs through them; that proves nothing |
| medium | Lines that say lines were lost (kernel, journald, rsyslog) were no doubt | a doubt on their gateway and day |
| medium | The pre-NAT address the parser adds was called an unused object | not counted for a platform that looks rules up after NAT |
| medium | A `LOG` of every packet: replies were simulated as connections, certain for rules that saw none | TCP lines that open no connection are not counted; other protocols are possible only, with the note `LOG_EVERY_PACKET` |
| medium | The year carried over from one file to the next, and a line out of order around New Year moved the year | per file; such a line is in the year before |
| low | Lines of every host in a central syslog file were matched against the policy | `--gateway` filters them; without it, several hosts make simulated connections possible only |
| low | Addresses a store kept as networks could never be certain | a network is placed as a whole |
| low | A garbled line without `OUT=` was taken for the firewall's own; a prefix with `IN=` won over the fields; `TRACE` and `ebtables` lines were connections | a doubt; the last `IN= OUT=` pair; their own reasons |

The note that the log's verdict is never applied in `fwshift usage` (the
lines carry none) stands, and is in the limits of the manual. The fixes were
not reviewed again; they have tests (the last section of `test_simulate.py`).

**Verified, and not**

* The tests: `tests/test_simulate.py` holds 54 tests, the suite 3303. The
  simulator against a walk through the rules on 30 random rulesets, in six
  worlds of what the rules the model holds approximately do: the certain rule
  decides in every world, and where none is certain the possible ones hold the
  one that decides (also with ports and zones unknown, and addresses as
  networks). A mutation check with 21 ways to break the simulator, the reader,
  the parser and the counting: 20 caught, and the one left is equivalent
  (`not match.loose` beside `match.covers`, which already holds it).
* **No log of a real host was read.** The line shapes follow the kernel source
  and the documentation of syslog and the journal; `NFLOG` lines (ulogd) are
  not read at all.

### 2026-10-12: version 0.14.0

The second release of *rule usage* (`docs/RULE_USAGE.md`): `fwshift usage`,
which rules, objects and services the logs of a Check Point firewall show
used.

**Built**

* `logreaders/checkpoint.py`: Log Exporter in its formats syslog (also behind
  a relay's header), splunk and cef, and the JSON answer of the Management API
  command `show-logs` (pages one after the other). Every line becomes a
  connection with the match table of the rules the gateway named, or a reason;
  a reason says whether the line may have been a connection (a doubt).
* `usage.py`: the store (SQLite; `runs`, `files`, `coverage`, `unplaced`,
  `records`, `rolled`, `kept`), reading into it (a file once, by its content;
  addresses beyond `--roll-up` per rule and side as their /24 or /64), the
  window of days, attribution by the uids of the rules on the way through the
  match table, counting inside the rule (every object that holds the address,
  through groups; every service that holds the protocol and port), the
  evidence, the comparison with hit counters, and the reports (text, JSON,
  one HTML page that needs nothing else).
* Model: `Rule.log_usage` (`LogUsage`), `Rule.changed` (Check Point
  `meta-info`), `Address.part_of` (the translated address of automatic NAT).
  Every Check Point rule also carries the uid of the layer the policy was read
  from (`checkpoint.policy_layer_uid`).
* Audit: `UNUSED_RULE` from the logs as well as from the counters,
  `UNUSED_RULE_OBJECT` and `UNUSED_RULE_SERVICE` (low; report only), one
  decision per rule from both sources; `--usage-store` and `--usage-gateway`
  for `fwshift audit` and `fwshift convert`.
* Command `fwshift usage`; the manual's section 15 and the command reference.
* Sample: `checkpoint_sample.log` (90 days of one gateway, written by
  `tests/tools/make_checkpoint_logs.py` from the sample policy), its report as
  a golden file. The sample's rule uids are now unique (the generator gave
  the rules of the inline layer the uids of the first rules of the main
  layer, which no management server does).

**What the platform made necessary**

* *The gateway decides.* Check Point logs name the rule of every layer; the
  connection is counted for that rule and nothing is simulated (that is 0.15).
* *A flattened table.* Log Exporter writes the match table column by column
  and leaves a column short where a rule has no name or a layer's implicit
  cleanup no uid; uids are put on rows only where their number fits.
* *Days, not files, are the evidence.* A rule is proven unused only when
  every gateway it is on logged connections that name a rule on every day of
  the window, at least one accepted one, and nothing of them could not be
  read; the rule's own age comes from `meta-info`.
* *The rule of the source, not its parts.* A rule split by access roles is
  one rule on Check Point: a part without connections, whose siblings had
  them, is reported by its sources.

**Sources**

Check Point's Log Exporter guide (format definitions, escaping) and CLI
reference (`cp_log_export`, `fwm logexport`, `fw log`), CheckMates threads
(inline layers, UTC, show-logs, the CSV export), and the parsers and test
fixtures of Elastic, Splunk Connect for Syslog, syslog-ng, Wazuh and Sekoia,
read and never run; fwanalyser and its Python port for what they read.

**Review**

*Round 22* by the independent reviewer, with repro scripts of its own and the
real fixture lines of the published parsers. 3 high, 6 medium, 7 low:

| | Finding | Fix |
|---|---|---|
| high | Lines that name a rule were skipped as no connection: a `packets` counter taken for an optimized drop, another blade's product (Application Control names the Network rule too), a line without a protocol. The day still counted, and the rule could be called unused | a line that names a rule is a connection of it whatever it lacks; what it lacks is "not in the log", and no member of that cell is called unused |
| high | The layer of the policy was found only from rules without a parent: a main layer that only applies inline layers, a policy read from an inline layer, an export without the layer's uid. Every allow rule could be called unused | the uid of the layer is on every rule; its row starts the chain wherever it is; without it, or without any connection that names the layer, the logs prove nothing |
| high | Gateways that never sent logs were not required, and `audit --usage-store` had no way to name them; cluster members log under their own names | `--usage-gateway`; `--gateway NAME=MEMBER,...`; the report names the gateways it judged by |
| medium | show-logs: the log's own rule fields were mixed into the rows | rows from their own objects |
| medium | Lines of Check Point formats that are not read (the gateway's syslog, leef, json, a relay's header) were no doubt | a doubt; the relay's header is read past |
| medium | Any line counted as a day logged; an exporter that sends drops only proved every allow rule unused | only connections that name a rule count; at least one accepted connection per gateway |
| medium | Reading into a large store was quadratic (the limit of addresses looked up in the records) | a table of the addresses kept; files read one at a time |
| medium | Splunk keys with a dash made the line unreadable | read |
| medium | Pages of show-logs one after the other were not read, and the file was marked as read | read; a file without a connection is not marked |
| low | The translated address of automatic NAT called an unused member | it is its object |
| low | A rule without `meta-info` was taken as old | no evidence, as for the counters |
| low | Tracebacks: a window off the calendar, a store with other columns, a record that cannot be read, a locked store | messages |
| low | Reasons carried text of the line (escapes, one reason per line) | fixed wording |
| low | A user with a comma was two users | kept whole |
| low | Overlapping files counted twice; lines without gateway and day stay against every window; a change after the window called "within" it | documented; reworded |

Not changed: a `Log Update` that would carry the final match table of a
connection the first line did not decide is skipped (not seen in any
fixture); objects or services that changed within the window are not
noticed (only the rule's own change is). The fixes were not reviewed again;
they have tests (the last section of `test_logs.py`).

**Verified, and not**

* The tests: `tests/test_logs.py` holds 39 tests, the suite 3246. The
  readers on the line shapes of the published fixtures; the regression cases
  of fwanalyser (a negated cell, two objects of one address, install-on); the
  counting of objects against a walk through the addresses on 25 random
  policies; every reason the logs prove nothing. A mutation check with 13 ways
  to break the reader, the store, the attribution and the audit: all caught.
  200,000 lines are read in about 18 seconds, 100,000 more into that store in
  9.
* **No log of a real gateway was read.** IPv6 logs, logs of implied rules and
  the json, leef and generic formats were not seen anywhere; the CSV export of
  SmartConsole and `fwm logexport` have no rule uid that any source shows.

### 2026-10-12: version 0.13.0

The first release of *rule usage* (`docs/RULE_USAGE.md`): what the source
calls each rule, where it is installed, Check Point access roles in the
model, and the hit counters of the firewall in the audit.

**Built**

* Model: `Rule.source_ids`, `Rule.targets`, `Rule.hits` (`HitCount`), shown
  by `--to json` and written by no emitter (*The neutral model* above).
* Check Point: every rule keeps its uid and the uid of its layer; a rule of an
  inline layer also the uid of the rule applying the layer and the uids of
  every rule on the way (`checkpoint.rule_path`); the implicit cleanup of an
  inline layer is marked as such. Install-on gateways are kept on the rule,
  for an inline rule where both rules are installed (none in common: written
  disabled). Hit counts of a rulebase exported with `show-hits`, and the
  creation and last change of a rule from `meta-info`.
* Check Point **access roles** in the source of a rule are networks with users
  (`ACCESS_ROLE`): a cell with roles of different users becomes one rule per
  set of users, and one for the plain addresses, in place and with the same
  action. Roles that also limit machines or a remote access client, roles in
  a destination or a negated source, roles without their content in the
  export and roles with a user named like a keyword stay unsupported. Inside
  an inline layer the users of both rules must agree. PAN-OS writes the users
  as `source-user`; the other targets write such rules disabled (`USER_MATCH`,
  as before for users from other sources).
* PAN-OS keeps the name and uuid of a rule and the Panorama targets that are
  not negated; FortiOS the policy ID and uuid.
* `hits.py`: hit counters from the answer of PAN-OS `show rule-hit-count`
  (XML API) and of the FortiOS monitor `firewall/policy` (JSON), given with
  `--hits FILE` to `fwshift audit` and `fwshift convert` (which then audits),
  matched to rules by `source_ids` and added up over several files.
* Audit: `UNUSED_RULE` (medium; an allow rule whose counter proves it unused
  for at least `usage_days`, 90) and `NO_USAGE_EVIDENCE` (info; no counter,
  a counter whose period is too short or not known, or that may leave out a
  firewall). `--hits-since` and `hits_since` give a start the counters do not
  give. The JSON findings carry `source_ids`. The header of `fwshift audit`
  and the report note `HIT_COUNTERS` say what was read.
* Sample: `checkpoint_sample.json` now has hit counts, creation dates, three
  access roles with content and the one without; its conversions, audit and
  matrix changed accordingly. The packet simulator of the tests treats a rule
  that matches users as matching no packet (packets there carry no user).
* Documents: `docs/RULE_USAGE.md`, the brief this release starts, with its
  review against the code and the plan to 0.17.0; the manual (sections 3, 5,
  7, 8, 13), README, TODO.

**What the platforms made necessary**

* *A zero is only as good as its period.* No answer says when it was read; the
  latest time it shows stands in, never later than the reading. PAN-OS gives
  the start of each counter; Check Point keeps counts for a period only, so
  the start is the later of the change of the rule and the earliest first
  hit in the export; FortiOS gives none, and its zeros prove nothing unless
  the user gives the start.
* *Counters belong to the firewall, policies to the manager.* A Panorama
  policy counted on one firewall, or a rule one of several answers does not
  count, proves nothing about the other firewalls.
* *Identities by name, not by position.* PAN-OS counts by rule name, FortiOS by
  uuid or policy ID (a policy ID only where the VDOM is known, and never
  against another uuid), Check Point by uid.
* *An access role is an intersection.* Its networks hold only for its users;
  a cell is a union. Merging the networks and users of several roles would
  let one role's networks through for another's users.

**Sources**

The brief written in another session from fwanalyser (Perl, and its Python
port), with its defects verified there; Check Point's admin guides (hit
count, access roles), its Ansible collection, Terraform provider and export
tools; PAN-OS release notes and pan.dev (rule UUIDs, rule hit counts) with
pan-os-python and a test fixture of the XSOAR integration; Fortinet's
documentation and community posts (policy uuid, the monitor answer, `iprope`)
with the Ansible collection. Code was read, never run. What rests on which,
and what is not confirmed, is in the review section of
`docs/RULE_USAGE.md` and below.

**Review**

*Round 21* by the independent reviewer, with repro scripts of its own. 1 high,
5 medium, 5 low:

| | Finding | Fix |
|---|---|---|
| high | An inline layer whose last rule is for some users (an access role) was taken as closed: its cleanup was left out, and what the layer dropped for other users reached the rules below | a rule for some users matches everything only when they are the users of the rule applying the layer; the same for the end of the main layer |
| medium | `UNUSED_RULE` where nobody knows how long the counter counted (Check Point, FortiOS, PAN-OS with every time 0) | `NO_USAGE_EVIDENCE` without a known start; Check Point's start from `meta-info` and the earliest first hit; `--hits-since` for the user's word |
| medium | With several answers, a zero was measured up to the latest time of any answer, not of its own | each counter keeps the reading of its own answer; zero on two is measured over the time both counted; a rule one answer does not count is incomplete |
| medium | `²` passes `isdigit()` and ends in a traceback | ASCII digits only |
| medium | An install-on reference the export does not resolve read as every gateway | kept by uid, and reported |
| medium | (release) no log entry for 0.13.0 | this one |
| low | a group named `unknown` or `pre-logon` written as the PAN-OS word for every user not signed in, or before signing in | refused, as `any` and `known-user` are |
| low | a FortiOS answer without a VDOM matched a policy of a VDOM by policy ID | by uuid only |
| low | a remote access client given as a uid made every role unsupported | resolved |
| low | the same answer given twice counted twice | refused |
| low | documentation drift (counts, TODO, README, the modification timestamp) | corrected |

Not changed: whether "Any user" in a Check Point access role also matches
traffic nobody signed in for is not confirmed; FWShift reads it as the
networks alone, since "All identified users" is the other choice the role
offers. Whether the FortiOS monitor counts IPv6 policies without
`ip_version` is not known (TODO). The fixes were not reviewed again; they
have tests (the last section of `test_usage.py`).

**Verified, and not**

* The tests: `tests/test_usage.py` holds 32 tests, the suite 3207. The
  access role split is compared with the cell as Check Point reads it (any
  member: an address, or a role's networks for its users) on 60 random cells,
  for every source and user. A mutation check with 12 ways to break the
  parser, the counters and the audit: all 12 caught.
* **Nothing was read from a real management server or firewall.** The shapes
  of access roles in an export (inferred from SDK code), of `meta-info` on a
  rule, of the PAN-OS and FortiOS answers (from one fixture and posts each)
  are as documented or published, not seen here.

### 2026-10-12: version 0.12.4

**Built**

* Windows, again: 0.12.3 asked for the password only when standard input was a
  terminal, but on Windows `isatty()` also says yes to `NUL`, a character
  device, so the test (standard input from `NUL`) still reached `getpass` and
  waited. The script now asks only when standard input is a terminal and, on
  Windows, a handle with a console mode (`GetConsoleMode`, through `ctypes`);
  whatever cannot be checked counts as nobody there.

**Verified, and not**

* A new test plays Windows on Linux: `NUL` without a console mode is not asked,
  a console is, a missing `msvcrt` is not, and `main` stops with the message
  without reaching `getpass`. It fails when the console check is taken out.
  mypy `--strict` passes, also with `--platform win32`. That the wait is gone
  on a real Windows is for the CI run on `windows-latest` to show.

### 2026-10-12: version 0.12.3

**Built**

* Windows: the script for a Management Center asked for the password with
  `getpass` when `FMC_PASSWORD` was not set. On Windows that reads the console
  whatever standard input is, so a run without a terminal (the test, a
  scheduled job) waited until it was killed instead of stopping. The script
  now asks only when standard input is a terminal, and otherwise stops with
  the message it gave before.

**Verified, and not**

* The tests of the script pass with Python 3.9 and 3.13 on Linux. That the
  wait is gone on Windows is for the CI run on `windows-latest` to show.

### 2026-10-12: version 0.12.2

**Built**

* Python 3.9 to 3.11: the SonicWall emitter (0.9.0) had a backslash in an
  expression of an f-string, which only Python 3.12 and later accept; on older
  releases no module that imports the command line could be loaded. The
  expression is now outside the f-string. A variable used for two types in the
  Barracuda emitter, which the mypy of Python 3.9 finds, is split in two.

**Verified, and not**

* Every source and test file compiles with Python 3.9, 3.10 and 3.11; the
  whole suite (3174 tests) passes with Python 3.9 and with 3.13; mypy
  `--strict` passes with the mypy that pip installs for 3.9, 3.10, 3.11 and
  3.12. The release steps now name the oldest Python.

### 2026-10-12: version 0.12.1

**Built**

* Windows: the tests failed on `windows-latest`, because Git there checks out
  text files with CRLF line endings and the loader for a Management Center
  (`fmc_loader.py`) went into the generated script with them. The repository
  now has a `.gitattributes` that keeps LF everywhere, the loader is read with
  its line endings made LF whatever the checkout did, the tests read and write
  their files as UTF-8 instead of the code page of the system, and the two
  tests that run the Barracuda script in `sh` are skipped where there is no
  POSIX shell.

**Verified, and not**

* The whole suite passes on a copy of the project with every text file
  converted to CRLF, as a Windows checkout without `.gitattributes` would have
  it. It was not run on Windows itself: the CI run on `windows-latest` is the
  check.

### 2026-10-12: version 0.12.0

**Built**

* Juniper SRX, read and written: `parsers/junos.py` and `emitters/junos.py`,
  as the format `junos`.
* Read: `show configuration | display set` (set and deactivate lines), or the
  configuration in braces, flattened to the same lines first. Zones and their
  interfaces; the global address book, books attached to zones and the books
  of zones; applications with terms and application sets; the predefined
  applications of a table; policies per pair of zones, global policies with
  their zones, the default policy; negation; deactivated policies and
  members; static, destination and source NAT with pools, brought back to
  the model's pre-NAT destinations.
* Written: set commands for `load set`: applications, the global address
  book, a policy per pair of zones in the order of the model, the rules at
  the end that are for every zone as global policies where that takes fewer
  policies, negation as `...-excluded` or as what is left, deactivated
  policies; NAT rule sets per zone and pair of zones, a destination NAT and
  its way back as static NAT.
* A sample, `junos_sample.conf`, written by `tests/tools/make_junos_sample.py`,
  with its conversions to every target, its audit and matrix, and the
  conversions of the other twelve samples to Juniper.
* The test that the manual and the code name the same findings now converts
  every sample to every target.
* Shared: a rule rewritten for a target that looks rules up after destination
  NAT, where the NAT rule translates only some of its services, is now
  reported for review (`NAT_DESTINATION_WIDENED`): for the other services it
  names the translated address, reached directly. Four reports of the
  FortiOS sample changed accordingly.

**What the platform made necessary**

* *Two places for policies.* A policy is for one pair of zones, and global
  policies come after those of every pair. Read: the pairs in order, then the
  global policies. Written: only rules at the end of the model can be global;
  where they go is chosen by the number of policies it takes.
* *Policies after destination NAT, source NAT after the policy.* As for the
  ASA: the parser brings policies back to the pre-NAT destination, the
  emitter takes them forward again for the NAT rules it writes.
* *Names per zone.* The same address name can mean different addresses in
  two zones; such objects keep their book in their name in the model.
* *Predefined applications that are not in the configuration.* A table of
  those whose definition the sources agree on; the rest make a policy
  unusable.
* *Two forms of one configuration, and groups.* The braces are flattened to
  set lines; a configuration whose security policy comes from groups not
  shown where they apply is refused with the export that shows them.

**Sources**

Juniper's documentation (security policies and their order, global policies,
address books and sets, predefined applications, application sets, NAT and
its order, static NAT, configuration groups, viewing the configuration) and
the Junos grammar of Batfish, with the Junos generators of Aerleon and
Capirca, read and never run. What comes from where, and what is assumed, is
in the table *Vendor behaviour the code relies on*.

**Review**

*Round 20* by the independent reviewer, with repro scripts of its own (3,000
mutated set configurations, 20,000 random token sequences in braces). 4 high,
5 medium, 9 low:

| | Finding | Fix |
|---|---|---|
| high | A bi-directional static NAT was written as static NAT, and the policies were not taken forward to the address the SRX sees after it: a deny for the public address no longer matched | they are |
| high | ICMPv6 types by name were read as ICMPv4 types (`echo-request` 8, not 128) | a table of ICMPv6 names; the judge corrected with it |
| high | A destination NAT and its way back written as static NAT, which the SRX applies before every destination NAT: an earlier port forward for the same address lost | not paired where an earlier destination NAT meets it |
| high | Several lists in one statement in braces multiplied: a few KB of input, gigabytes of memory | one list per statement, and blocks no deeper than 64 |
| medium | Deep braces and very long lines took minutes (the path rebuilt at every block, every prefix of a line looked up) | the path kept as it goes; only the depths that are deactivated looked up |
| medium | A global object whose name looks like an address took the place of that address in a NAT rule | such objects are renamed in the model |
| medium | A named book called like a zone and the book of that zone gave objects one name | told apart |
| medium | (shared) A rule for more services than its destination NAT, taken forward to the translated address for all of them, was only approximated | for review, on every target of that kind |
| low | `then` of a NAT rule on two lines (mapped port, persistent NAT) read as the last one only; an interzone rule that leaves no pair in the global part reported exact; `ZONES_EXPANDED` said too much; IPv6 addresses written another way refused; a short pool line reported as not read; a reserved prefix after cleaning a name; prompt lines in braces refused; groups shown by `display inheritance` refused; a zone named `any` read as every zone; the new codes not documented | merged; skipped as matching nothing; reworded; compared as addresses; ignored; checked after cleaning; dropped; read; not used; documented, and the test covers every sample and target |

Not changed: the ranking of source NAT rule sets by their `to` context is
not read (it changes what is translated, not what a policy allows). The
fixes were not reviewed again; they have tests (the last section of
`test_junos.py`).

**Verified, and not**

* The tests: `tests/test_junos.py` holds 120 tests, the suite
  3174. The parser is compared with an independent reading of the set
  lines on 100 random configurations, the emitter with the model on 60
  random models, the round trip on 30; the braces against their set lines.
  NAT has hand tests only. A mutation check with 12 ways to break parser and
  emitter: all 12 caught.
* **Nothing was loaded on an SRX.** The statements come from Juniper's
  documentation and from Batfish's grammar; the judge is written from the
  same reading.
* The largest unknowns: the exact predefined applications of a release;
  whether `display inheritance | display set` is accepted and what it prints
  for groups; names of 63 characters; `match from-zone` in global policies;
  the order of NAT rule sets of one context.

## To do

See [TODO.md](TODO.md): the firewall brands that are planned, one per
release, rule usage from hit counters and logs (designed in
[docs/RULE_USAGE.md](docs/RULE_USAGE.md), releases 0.13.0 to 0.17.0), and what
else is on the list for the audit, the matrix, the conversion and its
validation.
