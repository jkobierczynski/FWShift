# The FWShift lab

The lab puts a converted policy on a **real target** and checks it with **real connections**. It converts one small
synthetic policy (`policy/lab_panos.xml`, PAN-OS) for a target, loads the result there, sends a fixed set of test
connections between test hosts in three zones, and compares what came through with what the *source* policy decides.
Everything a run makes is destroyed at the end, also when a step fails.

```
            inside 10.20.1.0/24            dmz 10.20.2.0/24            outside 10.20.3.0/24
          in10 .10    in11 .11           dmz10 .10   dmz11 .11              out10 .10
              \          /                   \          /                       |
               +--------+------- the target: a cloud network, a VM, a firewall -+
```

| Tier | What | Targets | Needs | Cost |
|---|---|---|---|---|
| 1 | the cloud's own firewall, no image | `aws` (security groups), `azure` (NSGs), `gcp` (network firewall policy) | an account, Terraform or OpenTofu, the cloud's CLI | five small test hosts for the length of a run |
| 2 | images that are free, on your own Linux host | `nftables`, `iptables` (the kernel, no image), `routeros`, `opnsense`, `pfsense` (KVM) | root; QEMU/KVM and a base image for the last three | nothing |
| 3 | AWS Marketplace images, pay per hour | `fortigate`, `panos`, `vsrx`, `c8000v`, `asav`, `checkpoint` | an AWS account subscribed to the image | the image's hourly price and five small test hosts |

`python3 lab/lab.py list` shows the same, with the images of tier 3 that are not scripted and why.

## How a run decides

* **The plan** (`plan.json`): every pair of test hosts, both ways, for TCP 22, 80, 443, 8005, 8011, UDP 53, 123 and
  ICMP echo: 160 flows. What each should get comes from the source policy, through FWShift's own first-match
  simulation (`src/fwshift/simulate.py`); the test suite checks the plan against its separate judge.
* **Local flows**: in tiers 2 and 3 two hosts of one zone share a subnet and talk without the firewall: those 32 flows
  are sent and shown as `local`, and never asserted. That leaves 128 flows through the firewall. In tier 1 the cloud's
  firewall sits on every interface, so all 160 go through it.
* **Asserted flows**: a flow counts only when the source decides it surely, **every rule that might match it was
  converted exactly** (the conversion report says so), and no note of the report about the target's default (between
  zones, or inside one) applies to it. The others are still sent and shown: a difference there is one the report
  announced (`differs-announced`), not a failure. `python3 lab/lab.py plan TIER FIREWALL` lists them with the reason.
* **The probes** (`probe.py`, Python and ping only): each host answers on every test port of its test address and
  tries every flow of the plan from it. A TCP handshake, a UDP answer or an echo reply is `passed`; nothing within 3
  seconds is `blocked`; a TCP reset or an ICMP unreachable is `refused`. Security groups, NSGs and Google's firewall
  never reset, so in tier 1 a reset means the port was reached (it counts as passed); in tiers 2 and 3 a firewall
  rejects that way (it counts as blocked). A probe that cannot even bind its source address says `error`. Before the
  flows, each host checks itself (`probe.py selfcheck`): its answers listen, and it can bind its test address.
* **The result** (`summary.txt`, `summary.json`): `ok`, `FAIL`, `differs-announced`, `local`, `error`; the run passes
  when no asserted flow fails, every flow was tried, and the asserted flows hold both some that should pass and some
  that should be blocked (a run that only ever saw one kind shows nothing). A dry run says `DRY RUN`: its results are
  what the plan expects. Exit status 0 passed, 1 failed, 2 the run could not be made (or was interrupted).

Every run keeps its files in `lab-work/RUN` (or `--work`, or `FWLAB_WORK`): the conversion and its report, the plan,
the results, the summary, `commands.log` (every command that made or changed something), the Terraform state, and for
tier 3 what the firewall answered (`load.txt`).

```sh
python3 lab/lab.py plan tier1 aws                   # convert and plan only; makes nothing
python3 lab/lab.py run tier1 aws --dry-run          # convert and plan for real; only write down the other commands
python3 lab/lab.py check plan.json results.json     # check results again
```

## Teardown

Everything a run makes is torn down at the end: after a pass, a failure, a step that went wrong, Ctrl-C, or a `kill`
(SIGTERM, SIGHUP). An interrupt reaches the command that is running once (Terraform then stops and writes its state),
and the teardown itself is not interrupted. When it is done, `run.json` in the work folder says `torn_down`; the
teardown commands are in `commands.log`.

`--keep` leaves everything running at the end, to look at a failure (and pay for it). A kept run, or one whose
process was killed outright (`kill -9`, a machine that went down), is torn down from its work folder, which holds
`run.json` and the Terraform state:

```sh
python3 lab/lab.py destroy RUN                      # the run's id under lab-work, or the path of its work folder
python3 lab/lab.py destroy-all lab-work             # every run under the folder that is not torn down yet
```

When a teardown leaves something behind, the run lists what it still finds by the run's id. What carries the id
`fwshift-lab=RUN`: on AWS every resource (the provider's default tags, and the security groups the converted script
creates); on Azure the resource group, which holds everything; on Google Cloud the instances as a label (networks and
the firewall policy have the run's id in their names).

## Safety

* The policy and all addresses are synthetic (RFC 1918). No configuration of a real network goes in or out.
* The test hosts and firewalls are managed only from your own address (`--admin-cidr`, or what checkip.amazonaws.com
  sees), over SSH with a key made for the run. `--admin-cidr` takes one address; a network needs `--allow-wide-admin`.
  The test hosts' management interfaces accept nothing else and send nothing out (an egress deny on each cloud); the
  test traffic stays inside the lab network.
* Every run carries its id, and is torn down at the end (see Teardown).

## Tier 1: AWS, Azure, Google Cloud

```sh
python3 lab/lab.py run tier1 aws --region eu-west-1
python3 lab/lab.py run tier1 azure --region westeurope
python3 lab/lab.py run tier1 gcp --project my-project --region europe-west1
```

Needs `terraform` (1.5 or later) or `tofu`, `ssh`, and the CLI of the cloud (`aws`, `az`, `gcloud`) logged in to an
account where you may create networks and virtual machines. Each test host has two network interfaces: management
(public address) and test (in its zone's subnet). The converted policy goes on the test interfaces only:

* **AWS**: the converted script creates the security groups in the lab VPC; each test interface gets the groups whose
  `# attach` line holds its address. At the end the groups are taken off, emptied and deleted, then the VPC.
* **Azure**: the converted template is deployed into the lab's resource group, and each NSG is associated with the
  subnet of its zone (by the networks in the template's metadata). The teardown deletes the resource group. The test
  VMs log in with an RSA key (Azure takes no other kind). Three things that stop a new subscription:
  * Azure Resource Manager requires multi-factor authentication: when `az login` finds "no subscriptions" after an
    `AADSTS50076` message, sign in to the tenant itself, `az login --tenant TENANT_ID` (`--use-device-code` without a
    browser).
  * Popular regions refuse new subscriptions ("not accepting new customers", West Europe in October 2026), or do not
    offer them the VM size (`NotAvailableForSubscription`, North Europe). The regions where `Standard_B1s` is offered
    to you: `az vm list-skus --size Standard_B1s --all --query "[?!(restrictions[?type=='Location'])].locations[0]" -o tsv`.
    Germany West Central worked.
  * The quota: five vCPUs of the B family in the region (`az vm list-usage --location REGION -o table`).
* **Google Cloud**: the converted script creates the network firewall policy, which is associated with the lab's test
  network (enforcement order `BEFORE_CLASSIC_FIREWALL`, no VPC firewall rules). An organisation policy that forbids
  external addresses or enforces OS Login stops the run: use a project without them. Terraform logs in apart from
  gcloud: `gcloud auth login` and `gcloud auth application-default login`, and the Compute Engine API enabled in the
  project (`gcloud services enable compute.googleapis.com`).
* **AWS**: a user of its own for the lab, with `AmazonEC2FullAccess` and an access key for the CLI (`aws configure`),
  is enough; never a key of the root user.

## Tier 2: your own Linux host

```sh
sudo -E python3 lab/lab.py run tier2 nftables
sudo -E python3 lab/lab.py run tier2 iptables
sudo -E python3 lab/lab.py run tier2 routeros --image chr-base.qcow2 --ssh-key ~/.ssh/fwlab
sudo -E python3 lab/lab.py run tier2 opnsense --image opnsense-base.qcow2 --ssh-key ~/.ssh/fwlab --target-version 26.7
sudo -E python3 lab/lab.py run tier2 pfsense --image pfsense-base.qcow2 --ssh-key ~/.ssh/fwlab
```

The test hosts are network namespaces, with the firewall's `.1` in their zone as default route. The three bridges, one
per zone, live in a namespace of their own (`fwl-sw`), and so does QEMU: nothing of the lab is in the host's own
network, the host's rules (Docker's among them) never see lab traffic, and no setting of the host is changed. Root is
needed for the namespaces. The teardown deletes the namespaces, which takes everything in them along.

* **nftables, iptables**: the firewall is a network namespace whose interfaces are named after the zones; the
  converted ruleset is loaded there with `nft -f` or `iptables-restore`. No image, a few seconds, and it runs in the
  test suite where the host allows it (root, `ip`, `ping`, `nft`/`iptables`).
* **RouterOS, OPNsense, pfSense**: the firewall is a QEMU/KVM virtual machine started from a copy-on-write overlay of a
  base image, which stays as it was. NIC 1 is management on QEMU's user network (SSH from `127.0.0.1` of the switch
  namespace only); NICs 2, 3 and 4 are on the bridges of inside, dmz and outside. All NICs and the disk are virtio
  (vtnet0-3 and vtbd0 on the BSDs). Prepare each base image once:
  * **RouterOS CHR** (the raw image from mikrotik.com, converted with `qemu-img convert -O qcow2`): boot it once with
    the same NICs, set a password for `admin` and import the lab key (`/user ssh-keys import`); ether1 keeps DHCP. The
    run adds the addresses of ether2 to ether4, imports the converted script (it must end with RouterOS's line that the
    script was run), enables its jump, moves it to the top, and checks that its rules are there and enabled.
  * **OPNsense** (the nano image) and **pfSense CE** (installed from the ISO): assign LAN to vtnet0 (DHCP from QEMU),
    OPT1 to vtnet1 (10.20.1.1/24), OPT2 to vtnet2 (10.20.2.1/24) and WAN to vtnet3 (10.20.3.1/24) without *Block
    private networks*; enable SSH with key login for root and add the lab key. The run fetches `/conf/config.xml`, puts
    the converted areas in (as a restore of each area does, `tier2.merge_areas`), writes it back and reloads the filter
    (`configctl filter reload`; `/etc/rc.filter_configure_sync` on pfSense), then checks with `pfctl -sr` that the
    loaded rules name the lab's addresses. Give OPNsense the series of the image with `--target-version`.

## Tier 3: AWS Marketplace

```sh
python3 lab/lab.py run tier3 fortigate --region eu-west-1
python3 lab/lab.py run tier3 panos --ami ami-0123456789abcdef0
```

Subscribe to the image once in the AWS Marketplace console (that accepts its terms); the run looks for the newest image
whose name matches the pattern in `tier3.py`, or takes `--ami` (the id the subscription's launch page shows). The
firewall gets a management interface (SSH and HTTPS from your address) and one interface per zone at `.4`, with
source/destination checks off; each zone subnet's route table sends the other zones to the firewall's interface in it.
The run looks for the newest x86_64 image (and prints its name and product code), waits until the CLI answers that the
firewall is ready (`--boot-minutes`, 30), types the base configuration (interface addresses and zones, which FWShift
does not write; the images' default zones and rules are deleted first) and the converted policy over SSH, and fails on
any line the CLI refuses, or when the commit's success line does not come (`load.txt`, the lines sent in
`load.commands.txt`), or when a session answers almost nothing. A session gives up after 20 minutes. The ASAv's lines
are typed one at a time, each once its prompt is back (given them all at once, it closes the session), and after the
probes its own view is kept in `diagnose.txt` (interfaces, routes, rule hits, drops, two flows through `packet-tracer`). Each image bills for every hour it runs: a run takes 30 to 60 minutes, most of it the firewall
booting.

| Image | Target | Interfaces | Login |
|---|---|---|---|
| FortiGate-VM (PAYG) | `fortios`, zones mapped to port2-4 | port2, port3, port4 | `admin`, the run's key; addresses from the user data |
| Palo Alto VM-Series (PAYG Bundle 1, chosen by its product code: BYOL and the bundles share their name; Bundle 2 by `--ami`) | `panos` | ethernet1/1-1/3 (the example of older images deleted first, in a session whose answers do not count) | `admin` |
| Juniper vSRX (PAYG) | `junos` | ge-0/0/0-2 (the default zones are deleted first); ready once the forwarding engine has made them | `ec2-user` |
| Cisco Catalyst 8000V (IOS XE; the PAYG image with DNA Essentials, `Cisco-C8K-PAYG-ESS-*`) | `ios`, interfaces mapped to Gi2-4 | GigabitEthernet2-4, zone members from the output's comments | `ec2-user`; Day 0 in the user data gives the run's key as a `key-string` and allows the RSA signatures (IOS XE 26.02 takes no ssh-rsa by default) |
| Cisco ASAv | `asa` | the three data interfaces, by the names the ASAv gives them (read with `show interface ip brief`; on c5 not GigabitEthernet0/0-0/2), `inspect icmp` added; a Day 0 configuration turns on SSH on Management0/0 with the run's key (RSA 2048: the ASA's lines hold 511 characters); ssh allows its `ssh-rsa` host key | `admin` (privileged at login, by the Day 0 configuration, which also sets an enable password made for the run: `enable_password.txt` in the work folder) |
| Check Point All-In-One (PAYG: gateway and management on one instance; `--ami`, which Check Point's templates find by no name; m5.xlarge, 16 GB for the management API) | `checkpoint` | eth1-eth3, addresses set with `clish`; one `set simple-gateway` names every interface (eth0 too: it replaces the list), each data interface in its security zone, anti-spoofing off | `admin`, the run's key; bash, by the first-time setup (the image's `/etc/cloud_config.py`, as Check Point's Terraform module for a standalone calls it); ready when `api status` says the API is; FWShift's `mgmt_cli` script and the lab's `fwlab_load.sh` are copied over and run, then publish and install of `Standard`; boot allowed 60 minutes |

Not scripted, with the reason, in `python3 lab/lab.py list`: SonicWall, Stormshield, Sophos, Barracuda,
WatchGuard, Forcepoint, Meraki.

## In GitHub Actions

`.github/workflows/lab.yml` validates the Terraform modules and makes every run dry on each push that changes `lab/`.
Started by hand (*Actions > Lab > Run workflow*), it makes a real run of tier 1 or 3 in your account, in the
environment `lab`: give that environment a required reviewer in the repository settings, since a run costs money. It
logs in with OpenID Connect, so no key is stored. Allow only the default branch to deploy to that environment
(*Deployment branches*), so that a branch cannot change the workflow and use the clouds. Set these repository
variables:

| Cloud | Variables | What to make once |
|---|---|---|
| AWS | `LAB_AWS_ROLE` | an IAM OIDC provider for `token.actions.githubusercontent.com` and a role it may assume for `repo:OWNER/REPO:environment:lab`, allowed to manage EC2 (VPCs, subnets, route tables, security groups, instances, interfaces, key pairs, Elastic IPs) in the lab's region, with a maximum session duration of 3 hours (the workflow asks for that much: a tier 3 run and its teardown take long) |
| Azure | `LAB_AZURE_CLIENT_ID`, `LAB_AZURE_TENANT_ID`, `LAB_AZURE_SUBSCRIPTION_ID` | an app registration with a federated credential for the environment `lab`, Contributor on a subscription set aside for the lab |
| Google Cloud | `LAB_GCP_WORKLOAD_IDENTITY_PROVIDER`, `LAB_GCP_SERVICE_ACCOUNT`, `LAB_GCP_PROJECT` | a workload identity pool and provider for GitHub restricted to the repository, a service account with Compute Admin in the project (Compute Engine API enabled) |

The inputs are checked before use. After the run, a step that always runs tears down whatever is left
(`destroy-all`), also when the run was cancelled. The work folder is kept as the artifact `lab-results`, with the
Terraform state (to destroy by hand if even that failed) and without the run's private key. Tier 2 does not run there.

## What is verified, and what is not

* **Verified in real accounts** (0.32.1, by the author): AWS (eu-west-1), Azure (Germany West Central) and Google
  Cloud, each run passed and was torn down without leftovers. AWS and Azure: 144 asserted flows as the source decides,
  16 unasserted that came through as well. Google Cloud (0.32.0): 128 as the source decides, and the 32 inside a zone
  blocked, as the report announced. 0.32.1 writes them; its first run still saw them blocked, by the lab's routing of
  the own subnet (on the link, where Google Cloud only delivers through the gateway). With that routed through the
  gateway, Google Cloud passed with all 160 flows as the source decides. Tier 3: the FortiGate-VM (PAYG, FortiOS
  8.0.1) and the VM-Series (PAYG Bundle 1, PAN-OS 11.2.15) took every line of the converted policy and passed with 128
  flows through each as the source decides; so did the ASAv (PAYG, 9.24.10, 0.36.1), on its ninth run, and the
  vSRX (PAYG, the appsec bundle, Junos 23.4R2-S8.9, 0.36.1), on its fourth, and the Catalyst 8000V (PAYG, DNA
  Essentials, IOS XE 26.02.1, 0.36.3), on its third: the runs before them found what each needs of the lab
  (DEVELOPMENT.md, 0.36.1 and 0.36.3). `nftables` and `iptables` of
  tier 2 also passed on the author's own Debian.
* **Verified**: `nftables` and `iptables` of tier 2, for real: the converted policy in a network namespace, 128 flows
  through the kernel all as the source decides and 32 local ones; a ruleset that lets everything through fails the run;
  a SIGTERM in the middle of a run still tears everything down (all in `tests/test_lab.py`, which runs them where the
  host allows). Every other run is made dry in the tests and in the
  workflow: the conversion, the plan, the order of the commands, the variables against the Terraform modules, the
  first-boot script (`sh -n`), the merging of pfSense and OPNsense areas, the CLI sessions of tier 3.
* **Not verified**: no run of the VMs of tier 2 or of the last image of tier 3 (Check Point) has been
  made, nor a run of the workflow in GitHub. Their image names, logins and first boot, and the reload
  commands of OPNsense and pfSense, are taken from documentation. The first real run of each will find what is wrong.
  The Check Point script itself (FWShift's output for the lab policy) was loaded by hand on an R82.20 management
  server, published and verified; `fwlab_load.sh`, the interfaces and the install are what the first run will test.
