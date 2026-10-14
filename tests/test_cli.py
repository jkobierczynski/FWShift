# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from helpers import DATA

from fwshift import __version__
from fwshift.cli import VENDORS, detect_format, main
from fwshift.emitters.cisco import loader_source
from fwshift.emitters.forcepoint import loader_source as smc_loader_source

GOLDEN = DATA / "expected"
CASES = [
    ("panos_sample.xml", "fortios", "panos_to_fortios.conf"),
    ("fortios_sample.conf", "panos", "fortios_to_panos.set"),
    ("iptables_sample.rules", "panos", "iptables_to_panos.set"),
    ("iptables_sample.rules", "fortios", "iptables_to_fortios.conf"),
    ("panos_sample.xml", "iptables", "panos_to_iptables.rules"),
    ("fortios_sample.conf", "iptables", "fortios_to_iptables.rules"),
    ("checkpoint_sample.json", "panos", "checkpoint_to_panos.set"),
    ("checkpoint_sample.json", "fortios", "checkpoint_to_fortios.conf"),
    ("checkpoint_sample.json", "iptables", "checkpoint_to_iptables.rules"),
    ("checkpoint_sample.json", "checkpoint", "checkpoint_to_checkpoint.sh"),
    ("panos_sample.xml", "checkpoint", "panos_to_checkpoint.sh"),
    ("fortios_sample.conf", "checkpoint", "fortios_to_checkpoint.sh"),
    ("iptables_sample.rules", "checkpoint", "iptables_to_checkpoint.sh"),
    ("asa_sample.cfg", "panos", "asa_to_panos.set"),
    ("asa_sample.cfg", "fortios", "asa_to_fortios.conf"),
    ("asa_sample.cfg", "checkpoint", "asa_to_checkpoint.sh"),
    ("asa_sample.cfg", "iptables", "asa_to_iptables.rules"),
    ("asa_sample.cfg", "asa", "asa_to_asa.cfg"),
    ("panos_sample.xml", "asa", "panos_to_asa.cfg"),
    ("fortios_sample.conf", "asa", "fortios_to_asa.cfg"),
    ("checkpoint_sample.json", "asa", "checkpoint_to_asa.cfg"),
    ("iptables_sample.rules", "asa", "iptables_to_asa.cfg"),
    ("sophos_sample.xml", "sophos", "sophos_to_sophos.xml"),
    ("sophos_sample.xml", "panos", "sophos_to_panos.set"),
    ("sophos_sample.xml", "fortios", "sophos_to_fortios.conf"),
    ("sophos_sample.xml", "checkpoint", "sophos_to_checkpoint.sh"),
    ("sophos_sample.xml", "asa", "sophos_to_asa.cfg"),
    ("sophos_sample.xml", "iptables", "sophos_to_iptables.rules"),
    ("panos_sample.xml", "sophos", "panos_to_sophos.xml"),
    ("fortios_sample.conf", "sophos", "fortios_to_sophos.xml"),
    ("checkpoint_sample.json", "sophos", "checkpoint_to_sophos.xml"),
    ("asa_sample.cfg", "sophos", "asa_to_sophos.xml"),
    ("iptables_sample.rules", "sophos", "iptables_to_sophos.xml"),
    ("fmc_sample.json", "fmc", "fmc_to_fmc.policy.txt"),
    ("fmc_sample.json", "fdm", "fmc_to_fdm.json"),
    ("fmc_sample.json", "panos", "fmc_to_panos.set"),
    ("fmc_sample.json", "fortios", "fmc_to_fortios.conf"),
    ("fmc_sample.json", "checkpoint", "fmc_to_checkpoint.sh"),
    ("fmc_sample.json", "asa", "fmc_to_asa.cfg"),
    ("fmc_sample.json", "sophos", "fmc_to_sophos.xml"),
    ("fmc_sample.json", "iptables", "fmc_to_iptables.rules"),
    ("fdm_sample.txt", "fdm", "fdm_to_fdm.json"),
    ("fdm_sample.txt", "fmc", "fdm_to_fmc.policy.txt"),
    ("fdm_sample.txt", "panos", "fdm_to_panos.set"),
    ("fdm_sample.txt", "fortios", "fdm_to_fortios.conf"),
    ("fdm_sample.txt", "checkpoint", "fdm_to_checkpoint.sh"),
    ("fdm_sample.txt", "asa", "fdm_to_asa.cfg"),
    ("fdm_sample.txt", "sophos", "fdm_to_sophos.xml"),
    ("fdm_sample.txt", "iptables", "fdm_to_iptables.rules"),
    ("panos_sample.xml", "fmc", "panos_to_fmc.policy.txt"),
    ("fortios_sample.conf", "fmc", "fortios_to_fmc.policy.txt"),
    ("checkpoint_sample.json", "fmc", "checkpoint_to_fmc.policy.txt"),
    ("asa_sample.cfg", "fmc", "asa_to_fmc.policy.txt"),
    ("sophos_sample.xml", "fmc", "sophos_to_fmc.policy.txt"),
    ("iptables_sample.rules", "fmc", "iptables_to_fmc.policy.txt"),
    ("panos_sample.xml", "fdm", "panos_to_fdm.json"),
    ("fortios_sample.conf", "fdm", "fortios_to_fdm.json"),
    ("checkpoint_sample.json", "fdm", "checkpoint_to_fdm.json"),
    ("asa_sample.cfg", "fdm", "asa_to_fdm.json"),
    ("sophos_sample.xml", "fdm", "sophos_to_fdm.json"),
    ("iptables_sample.rules", "fdm", "iptables_to_fdm.json"),
    ("pfsense_sample.xml", "pfsense", "pfsense_to_pfsense.xml"),
    ("pfsense_sample.xml", "panos", "pfsense_to_panos.set"),
    ("pfsense_sample.xml", "fortios", "pfsense_to_fortios.conf"),
    ("pfsense_sample.xml", "checkpoint", "pfsense_to_checkpoint.sh"),
    ("pfsense_sample.xml", "asa", "pfsense_to_asa.cfg"),
    ("pfsense_sample.xml", "sophos", "pfsense_to_sophos.xml"),
    ("pfsense_sample.xml", "fmc", "pfsense_to_fmc.policy.txt"),
    ("pfsense_sample.xml", "fdm", "pfsense_to_fdm.json"),
    ("pfsense_sample.xml", "iptables", "pfsense_to_iptables.rules"),
    ("panos_sample.xml", "pfsense", "panos_to_pfsense.xml"),
    ("fortios_sample.conf", "pfsense", "fortios_to_pfsense.xml"),
    ("checkpoint_sample.json", "pfsense", "checkpoint_to_pfsense.xml"),
    ("asa_sample.cfg", "pfsense", "asa_to_pfsense.xml"),
    ("sophos_sample.xml", "pfsense", "sophos_to_pfsense.xml"),
    ("fmc_sample.json", "pfsense", "fmc_to_pfsense.xml"),
    ("fdm_sample.txt", "pfsense", "fdm_to_pfsense.xml"),
    ("iptables_sample.rules", "pfsense", "iptables_to_pfsense.xml"),
    ("sonicwall_sample.exp", "sonicwall", "sonicwall_to_sonicwall.cli"),
    ("sonicwall_sample.exp", "panos", "sonicwall_to_panos.set"),
    ("sonicwall_sample.exp", "fortios", "sonicwall_to_fortios.conf"),
    ("sonicwall_sample.exp", "checkpoint", "sonicwall_to_checkpoint.sh"),
    ("sonicwall_sample.exp", "asa", "sonicwall_to_asa.cfg"),
    ("sonicwall_sample.exp", "sophos", "sonicwall_to_sophos.xml"),
    ("sonicwall_sample.exp", "fmc", "sonicwall_to_fmc.policy.txt"),
    ("sonicwall_sample.exp", "fdm", "sonicwall_to_fdm.json"),
    ("sonicwall_sample.exp", "pfsense", "sonicwall_to_pfsense.xml"),
    ("sonicwall_sample.exp", "iptables", "sonicwall_to_iptables.rules"),
    ("panos_sample.xml", "sonicwall", "panos_to_sonicwall.cli"),
    ("fortios_sample.conf", "sonicwall", "fortios_to_sonicwall.cli"),
    ("checkpoint_sample.json", "sonicwall", "checkpoint_to_sonicwall.cli"),
    ("asa_sample.cfg", "sonicwall", "asa_to_sonicwall.cli"),
    ("sophos_sample.xml", "sonicwall", "sophos_to_sonicwall.cli"),
    ("fmc_sample.json", "sonicwall", "fmc_to_sonicwall.cli"),
    ("fdm_sample.txt", "sonicwall", "fdm_to_sonicwall.cli"),
    ("pfsense_sample.xml", "sonicwall", "pfsense_to_sonicwall.cli"),
    ("iptables_sample.rules", "sonicwall", "iptables_to_sonicwall.cli"),
    ("watchguard_sample.xml", "watchguard", "watchguard_to_watchguard.xml"),
    ("watchguard_sample.xml", "panos", "watchguard_to_panos.set"),
    ("watchguard_sample.xml", "fortios", "watchguard_to_fortios.conf"),
    ("watchguard_sample.xml", "checkpoint", "watchguard_to_checkpoint.sh"),
    ("watchguard_sample.xml", "asa", "watchguard_to_asa.cfg"),
    ("watchguard_sample.xml", "sophos", "watchguard_to_sophos.xml"),
    ("watchguard_sample.xml", "fmc", "watchguard_to_fmc.policy.txt"),
    ("watchguard_sample.xml", "fdm", "watchguard_to_fdm.json"),
    ("watchguard_sample.xml", "pfsense", "watchguard_to_pfsense.xml"),
    ("watchguard_sample.xml", "sonicwall", "watchguard_to_sonicwall.cli"),
    ("watchguard_sample.xml", "iptables", "watchguard_to_iptables.rules"),
    ("panos_sample.xml", "watchguard", "panos_to_watchguard.xml"),
    ("fortios_sample.conf", "watchguard", "fortios_to_watchguard.xml"),
    ("checkpoint_sample.json", "watchguard", "checkpoint_to_watchguard.xml"),
    ("asa_sample.cfg", "watchguard", "asa_to_watchguard.xml"),
    ("sophos_sample.xml", "watchguard", "sophos_to_watchguard.xml"),
    ("fmc_sample.json", "watchguard", "fmc_to_watchguard.xml"),
    ("fdm_sample.txt", "watchguard", "fdm_to_watchguard.xml"),
    ("pfsense_sample.xml", "watchguard", "pfsense_to_watchguard.xml"),
    ("sonicwall_sample.exp", "watchguard", "sonicwall_to_watchguard.xml"),
    ("iptables_sample.rules", "watchguard", "iptables_to_watchguard.xml"),
    ("barracuda_sample.json", "barracuda", "barracuda_to_barracuda.sh"),
    ("barracuda_sample.json", "panos", "barracuda_to_panos.set"),
    ("barracuda_sample.json", "fortios", "barracuda_to_fortios.conf"),
    ("barracuda_sample.json", "checkpoint", "barracuda_to_checkpoint.sh"),
    ("barracuda_sample.json", "asa", "barracuda_to_asa.cfg"),
    ("barracuda_sample.json", "sophos", "barracuda_to_sophos.xml"),
    ("barracuda_sample.json", "fmc", "barracuda_to_fmc.policy.txt"),
    ("barracuda_sample.json", "fdm", "barracuda_to_fdm.json"),
    ("barracuda_sample.json", "pfsense", "barracuda_to_pfsense.xml"),
    ("barracuda_sample.json", "sonicwall", "barracuda_to_sonicwall.cli"),
    ("barracuda_sample.json", "watchguard", "barracuda_to_watchguard.xml"),
    ("barracuda_sample.json", "iptables", "barracuda_to_iptables.rules"),
    ("panos_sample.xml", "barracuda", "panos_to_barracuda.sh"),
    ("fortios_sample.conf", "barracuda", "fortios_to_barracuda.sh"),
    ("checkpoint_sample.json", "barracuda", "checkpoint_to_barracuda.sh"),
    ("asa_sample.cfg", "barracuda", "asa_to_barracuda.sh"),
    ("sophos_sample.xml", "barracuda", "sophos_to_barracuda.sh"),
    ("fmc_sample.json", "barracuda", "fmc_to_barracuda.sh"),
    ("fdm_sample.txt", "barracuda", "fdm_to_barracuda.sh"),
    ("pfsense_sample.xml", "barracuda", "pfsense_to_barracuda.sh"),
    ("sonicwall_sample.exp", "barracuda", "sonicwall_to_barracuda.sh"),
    ("watchguard_sample.xml", "barracuda", "watchguard_to_barracuda.sh"),
    ("iptables_sample.rules", "barracuda", "iptables_to_barracuda.sh"),
    ("junos_sample.conf", "junos", "junos_to_junos.set.conf"),
    ("junos_sample.conf", "panos", "junos_to_panos.set"),
    ("junos_sample.conf", "fortios", "junos_to_fortios.conf"),
    ("junos_sample.conf", "checkpoint", "junos_to_checkpoint.sh"),
    ("junos_sample.conf", "asa", "junos_to_asa.cfg"),
    ("junos_sample.conf", "sophos", "junos_to_sophos.xml"),
    ("junos_sample.conf", "fmc", "junos_to_fmc.policy.txt"),
    ("junos_sample.conf", "fdm", "junos_to_fdm.json"),
    ("junos_sample.conf", "pfsense", "junos_to_pfsense.xml"),
    ("junos_sample.conf", "sonicwall", "junos_to_sonicwall.cli"),
    ("junos_sample.conf", "watchguard", "junos_to_watchguard.xml"),
    ("junos_sample.conf", "barracuda", "junos_to_barracuda.sh"),
    ("junos_sample.conf", "iptables", "junos_to_iptables.rules"),
    ("panos_sample.xml", "junos", "panos_to_junos.set.conf"),
    ("fortios_sample.conf", "junos", "fortios_to_junos.set.conf"),
    ("checkpoint_sample.json", "junos", "checkpoint_to_junos.set.conf"),
    ("asa_sample.cfg", "junos", "asa_to_junos.set.conf"),
    ("sophos_sample.xml", "junos", "sophos_to_junos.set.conf"),
    ("fmc_sample.json", "junos", "fmc_to_junos.set.conf"),
    ("fdm_sample.txt", "junos", "fdm_to_junos.set.conf"),
    ("pfsense_sample.xml", "junos", "pfsense_to_junos.set.conf"),
    ("sonicwall_sample.exp", "junos", "sonicwall_to_junos.set.conf"),
    ("watchguard_sample.xml", "junos", "watchguard_to_junos.set.conf"),
    ("barracuda_sample.json", "junos", "barracuda_to_junos.set.conf"),
    ("iptables_sample.rules", "junos", "iptables_to_junos.set.conf"),
    ("nftables_sample.nft", "nftables", "nftables_to_nftables.nft"),
    ("nftables_sample.nft", "panos", "nftables_to_panos.set"),
    ("nftables_sample.nft", "fortios", "nftables_to_fortios.conf"),
    ("nftables_sample.nft", "checkpoint", "nftables_to_checkpoint.sh"),
    ("nftables_sample.nft", "asa", "nftables_to_asa.cfg"),
    ("nftables_sample.nft", "sophos", "nftables_to_sophos.xml"),
    ("nftables_sample.nft", "fmc", "nftables_to_fmc.policy.txt"),
    ("nftables_sample.nft", "fdm", "nftables_to_fdm.json"),
    ("nftables_sample.nft", "pfsense", "nftables_to_pfsense.xml"),
    ("nftables_sample.nft", "sonicwall", "nftables_to_sonicwall.cli"),
    ("nftables_sample.nft", "watchguard", "nftables_to_watchguard.xml"),
    ("nftables_sample.nft", "barracuda", "nftables_to_barracuda.sh"),
    ("nftables_sample.nft", "iptables", "nftables_to_iptables.rules"),
    ("nftables_sample.nft", "junos", "nftables_to_junos.set.conf"),
    ("panos_sample.xml", "nftables", "panos_to_nftables.nft"),
    ("fortios_sample.conf", "nftables", "fortios_to_nftables.nft"),
    ("checkpoint_sample.json", "nftables", "checkpoint_to_nftables.nft"),
    ("asa_sample.cfg", "nftables", "asa_to_nftables.nft"),
    ("sophos_sample.xml", "nftables", "sophos_to_nftables.nft"),
    ("fmc_sample.json", "nftables", "fmc_to_nftables.nft"),
    ("fdm_sample.txt", "nftables", "fdm_to_nftables.nft"),
    ("pfsense_sample.xml", "nftables", "pfsense_to_nftables.nft"),
    ("sonicwall_sample.exp", "nftables", "sonicwall_to_nftables.nft"),
    ("watchguard_sample.xml", "nftables", "watchguard_to_nftables.nft"),
    ("barracuda_sample.json", "nftables", "barracuda_to_nftables.nft"),
    ("iptables_sample.rules", "nftables", "iptables_to_nftables.nft"),
    ("junos_sample.conf", "nftables", "junos_to_nftables.nft"),
    ("nsx_sample.json", "nsx", "nsx_to_nsx.json"),
    ("nsx_sample.json", "panos", "nsx_to_panos.set"),
    ("nsx_sample.json", "fortios", "nsx_to_fortios.conf"),
    ("nsx_sample.json", "checkpoint", "nsx_to_checkpoint.sh"),
    ("nsx_sample.json", "asa", "nsx_to_asa.cfg"),
    ("nsx_sample.json", "sophos", "nsx_to_sophos.xml"),
    ("nsx_sample.json", "fmc", "nsx_to_fmc.policy.txt"),
    ("nsx_sample.json", "fdm", "nsx_to_fdm.json"),
    ("nsx_sample.json", "pfsense", "nsx_to_pfsense.xml"),
    ("nsx_sample.json", "sonicwall", "nsx_to_sonicwall.cli"),
    ("nsx_sample.json", "watchguard", "nsx_to_watchguard.xml"),
    ("nsx_sample.json", "barracuda", "nsx_to_barracuda.sh"),
    ("nsx_sample.json", "iptables", "nsx_to_iptables.rules"),
    ("nsx_sample.json", "junos", "nsx_to_junos.set.conf"),
    ("nsx_sample.json", "nftables", "nsx_to_nftables.nft"),
    ("panos_sample.xml", "nsx", "panos_to_nsx.json"),
    ("fortios_sample.conf", "nsx", "fortios_to_nsx.json"),
    ("checkpoint_sample.json", "nsx", "checkpoint_to_nsx.json"),
    ("asa_sample.cfg", "nsx", "asa_to_nsx.json"),
    ("sophos_sample.xml", "nsx", "sophos_to_nsx.json"),
    ("fmc_sample.json", "nsx", "fmc_to_nsx.json"),
    ("fdm_sample.txt", "nsx", "fdm_to_nsx.json"),
    ("pfsense_sample.xml", "nsx", "pfsense_to_nsx.json"),
    ("sonicwall_sample.exp", "nsx", "sonicwall_to_nsx.json"),
    ("watchguard_sample.xml", "nsx", "watchguard_to_nsx.json"),
    ("barracuda_sample.json", "nsx", "barracuda_to_nsx.json"),
    ("iptables_sample.rules", "nsx", "iptables_to_nsx.json"),
    ("junos_sample.conf", "nsx", "junos_to_nsx.json"),
    ("nftables_sample.nft", "nsx", "nftables_to_nsx.json"),
    ("aws_sample.json", "aws", "aws_to_aws.sh"),
    ("aws_sample.json", "panos", "aws_to_panos.set"),
    ("aws_sample.json", "fortios", "aws_to_fortios.conf"),
    ("aws_sample.json", "checkpoint", "aws_to_checkpoint.sh"),
    ("aws_sample.json", "asa", "aws_to_asa.cfg"),
    ("aws_sample.json", "sophos", "aws_to_sophos.xml"),
    ("aws_sample.json", "fmc", "aws_to_fmc.policy.txt"),
    ("aws_sample.json", "fdm", "aws_to_fdm.json"),
    ("aws_sample.json", "pfsense", "aws_to_pfsense.xml"),
    ("aws_sample.json", "sonicwall", "aws_to_sonicwall.cli"),
    ("aws_sample.json", "watchguard", "aws_to_watchguard.xml"),
    ("aws_sample.json", "barracuda", "aws_to_barracuda.sh"),
    ("aws_sample.json", "iptables", "aws_to_iptables.rules"),
    ("aws_sample.json", "junos", "aws_to_junos.set.conf"),
    ("aws_sample.json", "nftables", "aws_to_nftables.nft"),
    ("aws_sample.json", "nsx", "aws_to_nsx.json"),
    ("panos_sample.xml", "aws", "panos_to_aws.sh"),
    ("fortios_sample.conf", "aws", "fortios_to_aws.sh"),
    ("checkpoint_sample.json", "aws", "checkpoint_to_aws.sh"),
    ("asa_sample.cfg", "aws", "asa_to_aws.sh"),
    ("sophos_sample.xml", "aws", "sophos_to_aws.sh"),
    ("fmc_sample.json", "aws", "fmc_to_aws.sh"),
    ("fdm_sample.txt", "aws", "fdm_to_aws.sh"),
    ("pfsense_sample.xml", "aws", "pfsense_to_aws.sh"),
    ("sonicwall_sample.exp", "aws", "sonicwall_to_aws.sh"),
    ("watchguard_sample.xml", "aws", "watchguard_to_aws.sh"),
    ("barracuda_sample.json", "aws", "barracuda_to_aws.sh"),
    ("iptables_sample.rules", "aws", "iptables_to_aws.sh"),
    ("junos_sample.conf", "aws", "junos_to_aws.sh"),
    ("nftables_sample.nft", "aws", "nftables_to_aws.sh"),
    ("nsx_sample.json", "aws", "nsx_to_aws.sh"),
    ("azure_sample.json", "azure", "azure_to_azure.json"),
    ("azure_sample.json", "panos", "azure_to_panos.set"),
    ("azure_sample.json", "fortios", "azure_to_fortios.conf"),
    ("azure_sample.json", "checkpoint", "azure_to_checkpoint.sh"),
    ("azure_sample.json", "asa", "azure_to_asa.cfg"),
    ("azure_sample.json", "sophos", "azure_to_sophos.xml"),
    ("azure_sample.json", "fmc", "azure_to_fmc.policy.txt"),
    ("azure_sample.json", "fdm", "azure_to_fdm.json"),
    ("azure_sample.json", "pfsense", "azure_to_pfsense.xml"),
    ("azure_sample.json", "sonicwall", "azure_to_sonicwall.cli"),
    ("azure_sample.json", "watchguard", "azure_to_watchguard.xml"),
    ("azure_sample.json", "barracuda", "azure_to_barracuda.sh"),
    ("azure_sample.json", "iptables", "azure_to_iptables.rules"),
    ("azure_sample.json", "junos", "azure_to_junos.set.conf"),
    ("azure_sample.json", "nftables", "azure_to_nftables.nft"),
    ("azure_sample.json", "nsx", "azure_to_nsx.json"),
    ("azure_sample.json", "aws", "azure_to_aws.sh"),
    ("panos_sample.xml", "azure", "panos_to_azure.json"),
    ("fortios_sample.conf", "azure", "fortios_to_azure.json"),
    ("checkpoint_sample.json", "azure", "checkpoint_to_azure.json"),
    ("asa_sample.cfg", "azure", "asa_to_azure.json"),
    ("sophos_sample.xml", "azure", "sophos_to_azure.json"),
    ("fmc_sample.json", "azure", "fmc_to_azure.json"),
    ("fdm_sample.txt", "azure", "fdm_to_azure.json"),
    ("pfsense_sample.xml", "azure", "pfsense_to_azure.json"),
    ("sonicwall_sample.exp", "azure", "sonicwall_to_azure.json"),
    ("watchguard_sample.xml", "azure", "watchguard_to_azure.json"),
    ("barracuda_sample.json", "azure", "barracuda_to_azure.json"),
    ("iptables_sample.rules", "azure", "iptables_to_azure.json"),
    ("junos_sample.conf", "azure", "junos_to_azure.json"),
    ("nftables_sample.nft", "azure", "nftables_to_azure.json"),
    ("nsx_sample.json", "azure", "nsx_to_azure.json"),
    ("aws_sample.json", "azure", "aws_to_azure.json"),
    ("routeros_sample.rsc", "routeros", "routeros_to_routeros.rsc"),
    ("routeros_sample.rsc", "panos", "routeros_to_panos.set"),
    ("routeros_sample.rsc", "fortios", "routeros_to_fortios.conf"),
    ("routeros_sample.rsc", "checkpoint", "routeros_to_checkpoint.sh"),
    ("routeros_sample.rsc", "asa", "routeros_to_asa.cfg"),
    ("routeros_sample.rsc", "sophos", "routeros_to_sophos.xml"),
    ("routeros_sample.rsc", "fmc", "routeros_to_fmc.policy.txt"),
    ("routeros_sample.rsc", "fdm", "routeros_to_fdm.json"),
    ("routeros_sample.rsc", "pfsense", "routeros_to_pfsense.xml"),
    ("routeros_sample.rsc", "sonicwall", "routeros_to_sonicwall.cli"),
    ("routeros_sample.rsc", "watchguard", "routeros_to_watchguard.xml"),
    ("routeros_sample.rsc", "barracuda", "routeros_to_barracuda.sh"),
    ("routeros_sample.rsc", "iptables", "routeros_to_iptables.rules"),
    ("routeros_sample.rsc", "junos", "routeros_to_junos.set.conf"),
    ("routeros_sample.rsc", "nftables", "routeros_to_nftables.nft"),
    ("routeros_sample.rsc", "nsx", "routeros_to_nsx.json"),
    ("routeros_sample.rsc", "aws", "routeros_to_aws.sh"),
    ("routeros_sample.rsc", "azure", "routeros_to_azure.json"),
    ("panos_sample.xml", "routeros", "panos_to_routeros.rsc"),
    ("fortios_sample.conf", "routeros", "fortios_to_routeros.rsc"),
    ("checkpoint_sample.json", "routeros", "checkpoint_to_routeros.rsc"),
    ("asa_sample.cfg", "routeros", "asa_to_routeros.rsc"),
    ("sophos_sample.xml", "routeros", "sophos_to_routeros.rsc"),
    ("fmc_sample.json", "routeros", "fmc_to_routeros.rsc"),
    ("fdm_sample.txt", "routeros", "fdm_to_routeros.rsc"),
    ("pfsense_sample.xml", "routeros", "pfsense_to_routeros.rsc"),
    ("sonicwall_sample.exp", "routeros", "sonicwall_to_routeros.rsc"),
    ("watchguard_sample.xml", "routeros", "watchguard_to_routeros.rsc"),
    ("barracuda_sample.json", "routeros", "barracuda_to_routeros.rsc"),
    ("iptables_sample.rules", "routeros", "iptables_to_routeros.rsc"),
    ("junos_sample.conf", "routeros", "junos_to_routeros.rsc"),
    ("nftables_sample.nft", "routeros", "nftables_to_routeros.rsc"),
    ("nsx_sample.json", "routeros", "nsx_to_routeros.rsc"),
    ("aws_sample.json", "routeros", "aws_to_routeros.rsc"),
    ("azure_sample.json", "routeros", "azure_to_routeros.rsc"),
    ("opnsense_sample.xml", "opnsense", "opnsense_to_opnsense.xml"),
    ("opnsense_sample.xml", "routeros", "opnsense_to_routeros.rsc"),
    ("opnsense_sample.xml", "panos", "opnsense_to_panos.set"),
    ("opnsense_sample.xml", "fortios", "opnsense_to_fortios.conf"),
    ("opnsense_sample.xml", "checkpoint", "opnsense_to_checkpoint.sh"),
    ("opnsense_sample.xml", "asa", "opnsense_to_asa.cfg"),
    ("opnsense_sample.xml", "sophos", "opnsense_to_sophos.xml"),
    ("opnsense_sample.xml", "fmc", "opnsense_to_fmc.policy.txt"),
    ("opnsense_sample.xml", "fdm", "opnsense_to_fdm.json"),
    ("opnsense_sample.xml", "pfsense", "opnsense_to_pfsense.xml"),
    ("opnsense_sample.xml", "sonicwall", "opnsense_to_sonicwall.cli"),
    ("opnsense_sample.xml", "watchguard", "opnsense_to_watchguard.xml"),
    ("opnsense_sample.xml", "barracuda", "opnsense_to_barracuda.sh"),
    ("opnsense_sample.xml", "iptables", "opnsense_to_iptables.rules"),
    ("opnsense_sample.xml", "junos", "opnsense_to_junos.set.conf"),
    ("opnsense_sample.xml", "nftables", "opnsense_to_nftables.nft"),
    ("opnsense_sample.xml", "nsx", "opnsense_to_nsx.json"),
    ("opnsense_sample.xml", "aws", "opnsense_to_aws.sh"),
    ("opnsense_sample.xml", "azure", "opnsense_to_azure.json"),
    ("routeros_sample.rsc", "opnsense", "routeros_to_opnsense.xml"),
    ("panos_sample.xml", "opnsense", "panos_to_opnsense.xml"),
    ("fortios_sample.conf", "opnsense", "fortios_to_opnsense.xml"),
    ("checkpoint_sample.json", "opnsense", "checkpoint_to_opnsense.xml"),
    ("asa_sample.cfg", "opnsense", "asa_to_opnsense.xml"),
    ("sophos_sample.xml", "opnsense", "sophos_to_opnsense.xml"),
    ("fmc_sample.json", "opnsense", "fmc_to_opnsense.xml"),
    ("fdm_sample.txt", "opnsense", "fdm_to_opnsense.xml"),
    ("pfsense_sample.xml", "opnsense", "pfsense_to_opnsense.xml"),
    ("sonicwall_sample.exp", "opnsense", "sonicwall_to_opnsense.xml"),
    ("watchguard_sample.xml", "opnsense", "watchguard_to_opnsense.xml"),
    ("barracuda_sample.json", "opnsense", "barracuda_to_opnsense.xml"),
    ("iptables_sample.rules", "opnsense", "iptables_to_opnsense.xml"),
    ("junos_sample.conf", "opnsense", "junos_to_opnsense.xml"),
    ("nftables_sample.nft", "opnsense", "nftables_to_opnsense.xml"),
    ("nsx_sample.json", "opnsense", "nsx_to_opnsense.xml"),
    ("aws_sample.json", "opnsense", "aws_to_opnsense.xml"),
    ("azure_sample.json", "opnsense", "azure_to_opnsense.xml"),
    ("forcepoint_sample.json", "forcepoint", "forcepoint_to_forcepoint.policy.txt"),
    ("forcepoint_sample.json", "opnsense", "forcepoint_to_opnsense.xml"),
    ("forcepoint_sample.json", "routeros", "forcepoint_to_routeros.rsc"),
    ("forcepoint_sample.json", "panos", "forcepoint_to_panos.set"),
    ("forcepoint_sample.json", "fortios", "forcepoint_to_fortios.conf"),
    ("forcepoint_sample.json", "checkpoint", "forcepoint_to_checkpoint.sh"),
    ("forcepoint_sample.json", "asa", "forcepoint_to_asa.cfg"),
    ("forcepoint_sample.json", "sophos", "forcepoint_to_sophos.xml"),
    ("forcepoint_sample.json", "fmc", "forcepoint_to_fmc.policy.txt"),
    ("forcepoint_sample.json", "fdm", "forcepoint_to_fdm.json"),
    ("forcepoint_sample.json", "pfsense", "forcepoint_to_pfsense.xml"),
    ("forcepoint_sample.json", "sonicwall", "forcepoint_to_sonicwall.cli"),
    ("forcepoint_sample.json", "watchguard", "forcepoint_to_watchguard.xml"),
    ("forcepoint_sample.json", "barracuda", "forcepoint_to_barracuda.sh"),
    ("forcepoint_sample.json", "iptables", "forcepoint_to_iptables.rules"),
    ("forcepoint_sample.json", "junos", "forcepoint_to_junos.set.conf"),
    ("forcepoint_sample.json", "nftables", "forcepoint_to_nftables.nft"),
    ("forcepoint_sample.json", "nsx", "forcepoint_to_nsx.json"),
    ("forcepoint_sample.json", "aws", "forcepoint_to_aws.sh"),
    ("forcepoint_sample.json", "azure", "forcepoint_to_azure.json"),
    ("routeros_sample.rsc", "forcepoint", "routeros_to_forcepoint.policy.txt"),
    ("opnsense_sample.xml", "forcepoint", "opnsense_to_forcepoint.policy.txt"),
    ("panos_sample.xml", "forcepoint", "panos_to_forcepoint.policy.txt"),
    ("fortios_sample.conf", "forcepoint", "fortios_to_forcepoint.policy.txt"),
    ("checkpoint_sample.json", "forcepoint", "checkpoint_to_forcepoint.policy.txt"),
    ("asa_sample.cfg", "forcepoint", "asa_to_forcepoint.policy.txt"),
    ("sophos_sample.xml", "forcepoint", "sophos_to_forcepoint.policy.txt"),
    ("fmc_sample.json", "forcepoint", "fmc_to_forcepoint.policy.txt"),
    ("fdm_sample.txt", "forcepoint", "fdm_to_forcepoint.policy.txt"),
    ("pfsense_sample.xml", "forcepoint", "pfsense_to_forcepoint.policy.txt"),
    ("sonicwall_sample.exp", "forcepoint", "sonicwall_to_forcepoint.policy.txt"),
    ("watchguard_sample.xml", "forcepoint", "watchguard_to_forcepoint.policy.txt"),
    ("barracuda_sample.json", "forcepoint", "barracuda_to_forcepoint.policy.txt"),
    ("iptables_sample.rules", "forcepoint", "iptables_to_forcepoint.policy.txt"),
    ("junos_sample.conf", "forcepoint", "junos_to_forcepoint.policy.txt"),
    ("nftables_sample.nft", "forcepoint", "nftables_to_forcepoint.policy.txt"),
    ("nsx_sample.json", "forcepoint", "nsx_to_forcepoint.policy.txt"),
    ("aws_sample.json", "forcepoint", "aws_to_forcepoint.policy.txt"),
    ("azure_sample.json", "forcepoint", "azure_to_forcepoint.policy.txt"),
    ("terraform_aws_sample.json", "forcepoint", "terraform_aws_to_forcepoint.policy.txt"),
    ("terraform_aws_sample.json", "opnsense", "terraform_aws_to_opnsense.xml"),
    ("terraform_aws_sample.json", "routeros", "terraform_aws_to_routeros.rsc"),
    ("terraform_aws_sample.json", "panos", "terraform_aws_to_panos.set"),
    ("terraform_aws_sample.json", "fortios", "terraform_aws_to_fortios.conf"),
    ("terraform_aws_sample.json", "checkpoint", "terraform_aws_to_checkpoint.sh"),
    ("terraform_aws_sample.json", "asa", "terraform_aws_to_asa.cfg"),
    ("terraform_aws_sample.json", "sophos", "terraform_aws_to_sophos.xml"),
    ("terraform_aws_sample.json", "fmc", "terraform_aws_to_fmc.policy.txt"),
    ("terraform_aws_sample.json", "fdm", "terraform_aws_to_fdm.json"),
    ("terraform_aws_sample.json", "pfsense", "terraform_aws_to_pfsense.xml"),
    ("terraform_aws_sample.json", "sonicwall", "terraform_aws_to_sonicwall.cli"),
    ("terraform_aws_sample.json", "watchguard", "terraform_aws_to_watchguard.xml"),
    ("terraform_aws_sample.json", "barracuda", "terraform_aws_to_barracuda.sh"),
    ("terraform_aws_sample.json", "iptables", "terraform_aws_to_iptables.rules"),
    ("terraform_aws_sample.json", "junos", "terraform_aws_to_junos.set.conf"),
    ("terraform_aws_sample.json", "nftables", "terraform_aws_to_nftables.nft"),
    ("terraform_aws_sample.json", "nsx", "terraform_aws_to_nsx.json"),
    ("terraform_aws_sample.json", "aws", "terraform_aws_to_aws.sh"),
    ("terraform_aws_sample.json", "azure", "terraform_aws_to_azure.json"),
    ("terraform_aws_sample.json", "terraform-aws", "terraform_aws_to_terraform_aws.tf"),
    ("terraform_aws_sample.json", "terraform-azure", "terraform_aws_to_terraform_azure.tf"),
    ("terraform_azure_sample.json", "forcepoint", "terraform_azure_to_forcepoint.policy.txt"),
    ("terraform_azure_sample.json", "opnsense", "terraform_azure_to_opnsense.xml"),
    ("terraform_azure_sample.json", "routeros", "terraform_azure_to_routeros.rsc"),
    ("terraform_azure_sample.json", "panos", "terraform_azure_to_panos.set"),
    ("terraform_azure_sample.json", "fortios", "terraform_azure_to_fortios.conf"),
    ("terraform_azure_sample.json", "checkpoint", "terraform_azure_to_checkpoint.sh"),
    ("terraform_azure_sample.json", "asa", "terraform_azure_to_asa.cfg"),
    ("terraform_azure_sample.json", "sophos", "terraform_azure_to_sophos.xml"),
    ("terraform_azure_sample.json", "fmc", "terraform_azure_to_fmc.policy.txt"),
    ("terraform_azure_sample.json", "fdm", "terraform_azure_to_fdm.json"),
    ("terraform_azure_sample.json", "pfsense", "terraform_azure_to_pfsense.xml"),
    ("terraform_azure_sample.json", "sonicwall", "terraform_azure_to_sonicwall.cli"),
    ("terraform_azure_sample.json", "watchguard", "terraform_azure_to_watchguard.xml"),
    ("terraform_azure_sample.json", "barracuda", "terraform_azure_to_barracuda.sh"),
    ("terraform_azure_sample.json", "iptables", "terraform_azure_to_iptables.rules"),
    ("terraform_azure_sample.json", "junos", "terraform_azure_to_junos.set.conf"),
    ("terraform_azure_sample.json", "nftables", "terraform_azure_to_nftables.nft"),
    ("terraform_azure_sample.json", "nsx", "terraform_azure_to_nsx.json"),
    ("terraform_azure_sample.json", "aws", "terraform_azure_to_aws.sh"),
    ("terraform_azure_sample.json", "azure", "terraform_azure_to_azure.json"),
    ("terraform_azure_sample.json", "terraform-aws", "terraform_azure_to_terraform_aws.tf"),
    ("terraform_azure_sample.json", "terraform-azure", "terraform_azure_to_terraform_azure.tf"),
    ("routeros_sample.rsc", "terraform-aws", "routeros_to_terraform_aws.tf"),
    ("routeros_sample.rsc", "terraform-azure", "routeros_to_terraform_azure.tf"),
    ("opnsense_sample.xml", "terraform-aws", "opnsense_to_terraform_aws.tf"),
    ("opnsense_sample.xml", "terraform-azure", "opnsense_to_terraform_azure.tf"),
    ("panos_sample.xml", "terraform-aws", "panos_to_terraform_aws.tf"),
    ("panos_sample.xml", "terraform-azure", "panos_to_terraform_azure.tf"),
    ("fortios_sample.conf", "terraform-aws", "fortios_to_terraform_aws.tf"),
    ("fortios_sample.conf", "terraform-azure", "fortios_to_terraform_azure.tf"),
    ("checkpoint_sample.json", "terraform-aws", "checkpoint_to_terraform_aws.tf"),
    ("checkpoint_sample.json", "terraform-azure", "checkpoint_to_terraform_azure.tf"),
    ("asa_sample.cfg", "terraform-aws", "asa_to_terraform_aws.tf"),
    ("asa_sample.cfg", "terraform-azure", "asa_to_terraform_azure.tf"),
    ("sophos_sample.xml", "terraform-aws", "sophos_to_terraform_aws.tf"),
    ("sophos_sample.xml", "terraform-azure", "sophos_to_terraform_azure.tf"),
    ("fmc_sample.json", "terraform-aws", "fmc_to_terraform_aws.tf"),
    ("fmc_sample.json", "terraform-azure", "fmc_to_terraform_azure.tf"),
    ("fdm_sample.txt", "terraform-aws", "fdm_to_terraform_aws.tf"),
    ("fdm_sample.txt", "terraform-azure", "fdm_to_terraform_azure.tf"),
    ("pfsense_sample.xml", "terraform-aws", "pfsense_to_terraform_aws.tf"),
    ("pfsense_sample.xml", "terraform-azure", "pfsense_to_terraform_azure.tf"),
    ("sonicwall_sample.exp", "terraform-aws", "sonicwall_to_terraform_aws.tf"),
    ("sonicwall_sample.exp", "terraform-azure", "sonicwall_to_terraform_azure.tf"),
    ("watchguard_sample.xml", "terraform-aws", "watchguard_to_terraform_aws.tf"),
    ("watchguard_sample.xml", "terraform-azure", "watchguard_to_terraform_azure.tf"),
    ("barracuda_sample.json", "terraform-aws", "barracuda_to_terraform_aws.tf"),
    ("barracuda_sample.json", "terraform-azure", "barracuda_to_terraform_azure.tf"),
    ("iptables_sample.rules", "terraform-aws", "iptables_to_terraform_aws.tf"),
    ("iptables_sample.rules", "terraform-azure", "iptables_to_terraform_azure.tf"),
    ("junos_sample.conf", "terraform-aws", "junos_to_terraform_aws.tf"),
    ("junos_sample.conf", "terraform-azure", "junos_to_terraform_azure.tf"),
    ("nftables_sample.nft", "terraform-aws", "nftables_to_terraform_aws.tf"),
    ("nftables_sample.nft", "terraform-azure", "nftables_to_terraform_azure.tf"),
    ("nsx_sample.json", "terraform-aws", "nsx_to_terraform_aws.tf"),
    ("nsx_sample.json", "terraform-azure", "nsx_to_terraform_azure.tf"),
    ("aws_sample.json", "terraform-aws", "aws_to_terraform_aws.tf"),
    ("aws_sample.json", "terraform-azure", "aws_to_terraform_azure.tf"),
    ("azure_sample.json", "terraform-aws", "azure_to_terraform_aws.tf"),
    ("azure_sample.json", "terraform-azure", "azure_to_terraform_azure.tf"),
    ("forcepoint_sample.json", "terraform-aws", "forcepoint_to_terraform_aws.tf"),
    ("forcepoint_sample.json", "terraform-azure", "forcepoint_to_terraform_azure.tf"),
    ("gcp_sample.json", "forcepoint", "gcp_to_forcepoint.policy.txt"),
    ("gcp_sample.json", "opnsense", "gcp_to_opnsense.xml"),
    ("gcp_sample.json", "routeros", "gcp_to_routeros.rsc"),
    ("gcp_sample.json", "panos", "gcp_to_panos.set"),
    ("gcp_sample.json", "fortios", "gcp_to_fortios.conf"),
    ("gcp_sample.json", "checkpoint", "gcp_to_checkpoint.sh"),
    ("gcp_sample.json", "asa", "gcp_to_asa.cfg"),
    ("gcp_sample.json", "sophos", "gcp_to_sophos.xml"),
    ("gcp_sample.json", "fmc", "gcp_to_fmc.policy.txt"),
    ("gcp_sample.json", "fdm", "gcp_to_fdm.json"),
    ("gcp_sample.json", "pfsense", "gcp_to_pfsense.xml"),
    ("gcp_sample.json", "sonicwall", "gcp_to_sonicwall.cli"),
    ("gcp_sample.json", "watchguard", "gcp_to_watchguard.xml"),
    ("gcp_sample.json", "barracuda", "gcp_to_barracuda.sh"),
    ("gcp_sample.json", "iptables", "gcp_to_iptables.rules"),
    ("gcp_sample.json", "junos", "gcp_to_junos.set.conf"),
    ("gcp_sample.json", "nftables", "gcp_to_nftables.nft"),
    ("gcp_sample.json", "nsx", "gcp_to_nsx.json"),
    ("gcp_sample.json", "aws", "gcp_to_aws.sh"),
    ("gcp_sample.json", "azure", "gcp_to_azure.json"),
    ("gcp_sample.json", "terraform-aws", "gcp_to_terraform_aws.tf"),
    ("gcp_sample.json", "terraform-azure", "gcp_to_terraform_azure.tf"),
    ("gcp_sample.json", "gcp", "gcp_to_gcp.sh"),
    ("gcp_sample.json", "terraform-google", "gcp_to_terraform_google.tf"),
    ("terraform_google_sample.json", "forcepoint", "terraform_google_to_forcepoint.policy.txt"),
    ("terraform_google_sample.json", "opnsense", "terraform_google_to_opnsense.xml"),
    ("terraform_google_sample.json", "routeros", "terraform_google_to_routeros.rsc"),
    ("terraform_google_sample.json", "panos", "terraform_google_to_panos.set"),
    ("terraform_google_sample.json", "fortios", "terraform_google_to_fortios.conf"),
    ("terraform_google_sample.json", "checkpoint", "terraform_google_to_checkpoint.sh"),
    ("terraform_google_sample.json", "asa", "terraform_google_to_asa.cfg"),
    ("terraform_google_sample.json", "sophos", "terraform_google_to_sophos.xml"),
    ("terraform_google_sample.json", "fmc", "terraform_google_to_fmc.policy.txt"),
    ("terraform_google_sample.json", "fdm", "terraform_google_to_fdm.json"),
    ("terraform_google_sample.json", "pfsense", "terraform_google_to_pfsense.xml"),
    ("terraform_google_sample.json", "sonicwall", "terraform_google_to_sonicwall.cli"),
    ("terraform_google_sample.json", "watchguard", "terraform_google_to_watchguard.xml"),
    ("terraform_google_sample.json", "barracuda", "terraform_google_to_barracuda.sh"),
    ("terraform_google_sample.json", "iptables", "terraform_google_to_iptables.rules"),
    ("terraform_google_sample.json", "junos", "terraform_google_to_junos.set.conf"),
    ("terraform_google_sample.json", "nftables", "terraform_google_to_nftables.nft"),
    ("terraform_google_sample.json", "nsx", "terraform_google_to_nsx.json"),
    ("terraform_google_sample.json", "aws", "terraform_google_to_aws.sh"),
    ("terraform_google_sample.json", "azure", "terraform_google_to_azure.json"),
    ("terraform_google_sample.json", "terraform-aws", "terraform_google_to_terraform_aws.tf"),
    ("terraform_google_sample.json", "terraform-azure", "terraform_google_to_terraform_azure.tf"),
    ("terraform_google_sample.json", "gcp", "terraform_google_to_gcp.sh"),
    ("terraform_google_sample.json", "terraform-google", "terraform_google_to_terraform_google.tf"),
    ("routeros_sample.rsc", "gcp", "routeros_to_gcp.sh"),
    ("routeros_sample.rsc", "terraform-google", "routeros_to_terraform_google.tf"),
    ("opnsense_sample.xml", "gcp", "opnsense_to_gcp.sh"),
    ("opnsense_sample.xml", "terraform-google", "opnsense_to_terraform_google.tf"),
    ("panos_sample.xml", "gcp", "panos_to_gcp.sh"),
    ("panos_sample.xml", "terraform-google", "panos_to_terraform_google.tf"),
    ("fortios_sample.conf", "gcp", "fortios_to_gcp.sh"),
    ("fortios_sample.conf", "terraform-google", "fortios_to_terraform_google.tf"),
    ("checkpoint_sample.json", "gcp", "checkpoint_to_gcp.sh"),
    ("checkpoint_sample.json", "terraform-google", "checkpoint_to_terraform_google.tf"),
    ("asa_sample.cfg", "gcp", "asa_to_gcp.sh"),
    ("asa_sample.cfg", "terraform-google", "asa_to_terraform_google.tf"),
    ("sophos_sample.xml", "gcp", "sophos_to_gcp.sh"),
    ("sophos_sample.xml", "terraform-google", "sophos_to_terraform_google.tf"),
    ("fmc_sample.json", "gcp", "fmc_to_gcp.sh"),
    ("fmc_sample.json", "terraform-google", "fmc_to_terraform_google.tf"),
    ("fdm_sample.txt", "gcp", "fdm_to_gcp.sh"),
    ("fdm_sample.txt", "terraform-google", "fdm_to_terraform_google.tf"),
    ("pfsense_sample.xml", "gcp", "pfsense_to_gcp.sh"),
    ("pfsense_sample.xml", "terraform-google", "pfsense_to_terraform_google.tf"),
    ("sonicwall_sample.exp", "gcp", "sonicwall_to_gcp.sh"),
    ("sonicwall_sample.exp", "terraform-google", "sonicwall_to_terraform_google.tf"),
    ("watchguard_sample.xml", "gcp", "watchguard_to_gcp.sh"),
    ("watchguard_sample.xml", "terraform-google", "watchguard_to_terraform_google.tf"),
    ("barracuda_sample.json", "gcp", "barracuda_to_gcp.sh"),
    ("barracuda_sample.json", "terraform-google", "barracuda_to_terraform_google.tf"),
    ("iptables_sample.rules", "gcp", "iptables_to_gcp.sh"),
    ("iptables_sample.rules", "terraform-google", "iptables_to_terraform_google.tf"),
    ("junos_sample.conf", "gcp", "junos_to_gcp.sh"),
    ("junos_sample.conf", "terraform-google", "junos_to_terraform_google.tf"),
    ("nftables_sample.nft", "gcp", "nftables_to_gcp.sh"),
    ("nftables_sample.nft", "terraform-google", "nftables_to_terraform_google.tf"),
    ("nsx_sample.json", "gcp", "nsx_to_gcp.sh"),
    ("nsx_sample.json", "terraform-google", "nsx_to_terraform_google.tf"),
    ("aws_sample.json", "gcp", "aws_to_gcp.sh"),
    ("aws_sample.json", "terraform-google", "aws_to_terraform_google.tf"),
    ("azure_sample.json", "gcp", "azure_to_gcp.sh"),
    ("azure_sample.json", "terraform-google", "azure_to_terraform_google.tf"),
    ("terraform_aws_sample.json", "gcp", "terraform_aws_to_gcp.sh"),
    ("terraform_aws_sample.json", "terraform-google", "terraform_aws_to_terraform_google.tf"),
    ("terraform_azure_sample.json", "gcp", "terraform_azure_to_gcp.sh"),
    ("terraform_azure_sample.json", "terraform-google", "terraform_azure_to_terraform_google.tf"),
    ("forcepoint_sample.json", "gcp", "forcepoint_to_gcp.sh"),
    ("forcepoint_sample.json", "terraform-google", "forcepoint_to_terraform_google.tf"),
    ("ios_sample.cfg", "forcepoint", "ios_to_forcepoint.policy.txt"),
    ("ios_sample.cfg", "opnsense", "ios_to_opnsense.xml"),
    ("ios_sample.cfg", "routeros", "ios_to_routeros.rsc"),
    ("ios_sample.cfg", "panos", "ios_to_panos.set"),
    ("ios_sample.cfg", "fortios", "ios_to_fortios.conf"),
    ("ios_sample.cfg", "checkpoint", "ios_to_checkpoint.sh"),
    ("ios_sample.cfg", "asa", "ios_to_asa.cfg"),
    ("ios_sample.cfg", "sophos", "ios_to_sophos.xml"),
    ("ios_sample.cfg", "fmc", "ios_to_fmc.policy.txt"),
    ("ios_sample.cfg", "fdm", "ios_to_fdm.json"),
    ("ios_sample.cfg", "pfsense", "ios_to_pfsense.xml"),
    ("ios_sample.cfg", "sonicwall", "ios_to_sonicwall.cli"),
    ("ios_sample.cfg", "watchguard", "ios_to_watchguard.xml"),
    ("ios_sample.cfg", "barracuda", "ios_to_barracuda.sh"),
    ("ios_sample.cfg", "iptables", "ios_to_iptables.rules"),
    ("ios_sample.cfg", "nftables", "ios_to_nftables.nft"),
    ("ios_sample.cfg", "nsx", "ios_to_nsx.json"),
    ("ios_sample.cfg", "aws", "ios_to_aws.sh"),
    ("ios_sample.cfg", "azure", "ios_to_azure.json"),
    ("ios_sample.cfg", "terraform-aws", "ios_to_terraform_aws.tf"),
    ("ios_sample.cfg", "terraform-azure", "ios_to_terraform_azure.tf"),
    ("ios_sample.cfg", "gcp", "ios_to_gcp.sh"),
    ("ios_sample.cfg", "terraform-google", "ios_to_terraform_google.tf"),
    ("ios_sample.cfg", "junos", "ios_to_junos.set.conf"),
    ("ios_sample.cfg", "ios", "ios_to_ios.cfg"),
    ("asa_sample.cfg", "ios", "asa_to_ios.cfg"),
    ("aws_sample.json", "ios", "aws_to_ios.cfg"),
    ("azure_sample.json", "ios", "azure_to_ios.cfg"),
    ("barracuda_sample.json", "ios", "barracuda_to_ios.cfg"),
    ("checkpoint_sample.json", "ios", "checkpoint_to_ios.cfg"),
    ("fdm_sample.txt", "ios", "fdm_to_ios.cfg"),
    ("fmc_sample.json", "ios", "fmc_to_ios.cfg"),
    ("forcepoint_sample.json", "ios", "forcepoint_to_ios.cfg"),
    ("fortios_sample.conf", "ios", "fortios_to_ios.cfg"),
    ("gcp_sample.json", "ios", "gcp_to_ios.cfg"),
    ("iptables_sample.rules", "ios", "iptables_to_ios.cfg"),
    ("junos_sample.conf", "ios", "junos_to_ios.cfg"),
    ("nftables_sample.nft", "ios", "nftables_to_ios.cfg"),
    ("nsx_sample.json", "ios", "nsx_to_ios.cfg"),
    ("opnsense_sample.xml", "ios", "opnsense_to_ios.cfg"),
    ("panos_sample.xml", "ios", "panos_to_ios.cfg"),
    ("pfsense_sample.xml", "ios", "pfsense_to_ios.cfg"),
    ("routeros_sample.rsc", "ios", "routeros_to_ios.cfg"),
    ("sonicwall_sample.exp", "ios", "sonicwall_to_ios.cfg"),
    ("sophos_sample.xml", "ios", "sophos_to_ios.cfg"),
    ("terraform_aws_sample.json", "ios", "terraform_aws_to_ios.cfg"),
    ("terraform_azure_sample.json", "ios", "terraform_azure_to_ios.cfg"),
    ("terraform_google_sample.json", "ios", "terraform_google_to_ios.cfg"),
    ("watchguard_sample.xml", "ios", "watchguard_to_ios.cfg"),
    ("huawei_sample.cfg", "forcepoint", "huawei_to_forcepoint.policy.txt"),
    ("huawei_sample.cfg", "opnsense", "huawei_to_opnsense.xml"),
    ("huawei_sample.cfg", "routeros", "huawei_to_routeros.rsc"),
    ("huawei_sample.cfg", "panos", "huawei_to_panos.set"),
    ("huawei_sample.cfg", "fortios", "huawei_to_fortios.conf"),
    ("huawei_sample.cfg", "checkpoint", "huawei_to_checkpoint.sh"),
    ("huawei_sample.cfg", "asa", "huawei_to_asa.cfg"),
    ("huawei_sample.cfg", "sophos", "huawei_to_sophos.xml"),
    ("huawei_sample.cfg", "fmc", "huawei_to_fmc.policy.txt"),
    ("huawei_sample.cfg", "fdm", "huawei_to_fdm.json"),
    ("huawei_sample.cfg", "pfsense", "huawei_to_pfsense.xml"),
    ("huawei_sample.cfg", "sonicwall", "huawei_to_sonicwall.cli"),
    ("huawei_sample.cfg", "watchguard", "huawei_to_watchguard.xml"),
    ("huawei_sample.cfg", "barracuda", "huawei_to_barracuda.sh"),
    ("huawei_sample.cfg", "iptables", "huawei_to_iptables.rules"),
    ("huawei_sample.cfg", "nftables", "huawei_to_nftables.nft"),
    ("huawei_sample.cfg", "nsx", "huawei_to_nsx.json"),
    ("huawei_sample.cfg", "aws", "huawei_to_aws.sh"),
    ("huawei_sample.cfg", "azure", "huawei_to_azure.json"),
    ("huawei_sample.cfg", "terraform-aws", "huawei_to_terraform_aws.tf"),
    ("huawei_sample.cfg", "terraform-azure", "huawei_to_terraform_azure.tf"),
    ("huawei_sample.cfg", "gcp", "huawei_to_gcp.sh"),
    ("huawei_sample.cfg", "terraform-google", "huawei_to_terraform_google.tf"),
    ("huawei_sample.cfg", "junos", "huawei_to_junos.set.conf"),
    ("huawei_sample.cfg", "ios", "huawei_to_ios.cfg"),
    ("huawei_sample.cfg", "huawei", "huawei_to_huawei.cfg"),
    ("ios_sample.cfg", "huawei", "ios_to_huawei.cfg"),
    ("asa_sample.cfg", "huawei", "asa_to_huawei.cfg"),
    ("aws_sample.json", "huawei", "aws_to_huawei.cfg"),
    ("azure_sample.json", "huawei", "azure_to_huawei.cfg"),
    ("barracuda_sample.json", "huawei", "barracuda_to_huawei.cfg"),
    ("checkpoint_sample.json", "huawei", "checkpoint_to_huawei.cfg"),
    ("fdm_sample.txt", "huawei", "fdm_to_huawei.cfg"),
    ("fmc_sample.json", "huawei", "fmc_to_huawei.cfg"),
    ("forcepoint_sample.json", "huawei", "forcepoint_to_huawei.cfg"),
    ("fortios_sample.conf", "huawei", "fortios_to_huawei.cfg"),
    ("gcp_sample.json", "huawei", "gcp_to_huawei.cfg"),
    ("iptables_sample.rules", "huawei", "iptables_to_huawei.cfg"),
    ("junos_sample.conf", "huawei", "junos_to_huawei.cfg"),
    ("nftables_sample.nft", "huawei", "nftables_to_huawei.cfg"),
    ("nsx_sample.json", "huawei", "nsx_to_huawei.cfg"),
    ("opnsense_sample.xml", "huawei", "opnsense_to_huawei.cfg"),
    ("panos_sample.xml", "huawei", "panos_to_huawei.cfg"),
    ("pfsense_sample.xml", "huawei", "pfsense_to_huawei.cfg"),
    ("routeros_sample.rsc", "huawei", "routeros_to_huawei.cfg"),
    ("sonicwall_sample.exp", "huawei", "sonicwall_to_huawei.cfg"),
    ("sophos_sample.xml", "huawei", "sophos_to_huawei.cfg"),
    ("terraform_aws_sample.json", "huawei", "terraform_aws_to_huawei.cfg"),
    ("terraform_azure_sample.json", "huawei", "terraform_azure_to_huawei.cfg"),
    ("terraform_google_sample.json", "huawei", "terraform_google_to_huawei.cfg"),
    ("watchguard_sample.xml", "huawei", "watchguard_to_huawei.cfg"),
    ("stormshield_sample.tgz", "forcepoint", "stormshield_to_forcepoint.policy.txt"),
    ("stormshield_sample.tgz", "opnsense", "stormshield_to_opnsense.xml"),
    ("stormshield_sample.tgz", "routeros", "stormshield_to_routeros.rsc"),
    ("stormshield_sample.tgz", "panos", "stormshield_to_panos.set"),
    ("stormshield_sample.tgz", "fortios", "stormshield_to_fortios.conf"),
    ("stormshield_sample.tgz", "checkpoint", "stormshield_to_checkpoint.sh"),
    ("stormshield_sample.tgz", "asa", "stormshield_to_asa.cfg"),
    ("stormshield_sample.tgz", "sophos", "stormshield_to_sophos.xml"),
    ("stormshield_sample.tgz", "fmc", "stormshield_to_fmc.policy.txt"),
    ("stormshield_sample.tgz", "fdm", "stormshield_to_fdm.json"),
    ("stormshield_sample.tgz", "pfsense", "stormshield_to_pfsense.xml"),
    ("stormshield_sample.tgz", "sonicwall", "stormshield_to_sonicwall.cli"),
    ("stormshield_sample.tgz", "watchguard", "stormshield_to_watchguard.xml"),
    ("stormshield_sample.tgz", "barracuda", "stormshield_to_barracuda.sh"),
    ("stormshield_sample.tgz", "iptables", "stormshield_to_iptables.rules"),
    ("stormshield_sample.tgz", "nftables", "stormshield_to_nftables.nft"),
    ("stormshield_sample.tgz", "nsx", "stormshield_to_nsx.json"),
    ("stormshield_sample.tgz", "aws", "stormshield_to_aws.sh"),
    ("stormshield_sample.tgz", "azure", "stormshield_to_azure.json"),
    ("stormshield_sample.tgz", "terraform-aws", "stormshield_to_terraform_aws.tf"),
    ("stormshield_sample.tgz", "terraform-azure", "stormshield_to_terraform_azure.tf"),
    ("stormshield_sample.tgz", "gcp", "stormshield_to_gcp.sh"),
    ("stormshield_sample.tgz", "terraform-google", "stormshield_to_terraform_google.tf"),
    ("stormshield_sample.tgz", "junos", "stormshield_to_junos.set.conf"),
    ("stormshield_sample.tgz", "ios", "stormshield_to_ios.cfg"),
    ("stormshield_sample.tgz", "huawei", "stormshield_to_huawei.cfg"),
    ("stormshield_sample.tgz", "stormshield", "stormshield_to_stormshield.script"),
    ("huawei_sample.cfg", "stormshield", "huawei_to_stormshield.script"),
    ("ios_sample.cfg", "stormshield", "ios_to_stormshield.script"),
    ("asa_sample.cfg", "stormshield", "asa_to_stormshield.script"),
    ("aws_sample.json", "stormshield", "aws_to_stormshield.script"),
    ("azure_sample.json", "stormshield", "azure_to_stormshield.script"),
    ("barracuda_sample.json", "stormshield", "barracuda_to_stormshield.script"),
    ("checkpoint_sample.json", "stormshield", "checkpoint_to_stormshield.script"),
    ("fdm_sample.txt", "stormshield", "fdm_to_stormshield.script"),
    ("fmc_sample.json", "stormshield", "fmc_to_stormshield.script"),
    ("forcepoint_sample.json", "stormshield", "forcepoint_to_stormshield.script"),
    ("fortios_sample.conf", "stormshield", "fortios_to_stormshield.script"),
    ("gcp_sample.json", "stormshield", "gcp_to_stormshield.script"),
    ("iptables_sample.rules", "stormshield", "iptables_to_stormshield.script"),
    ("junos_sample.conf", "stormshield", "junos_to_stormshield.script"),
    ("nftables_sample.nft", "stormshield", "nftables_to_stormshield.script"),
    ("nsx_sample.json", "stormshield", "nsx_to_stormshield.script"),
    ("opnsense_sample.xml", "stormshield", "opnsense_to_stormshield.script"),
    ("panos_sample.xml", "stormshield", "panos_to_stormshield.script"),
    ("pfsense_sample.xml", "stormshield", "pfsense_to_stormshield.script"),
    ("routeros_sample.rsc", "stormshield", "routeros_to_stormshield.script"),
    ("sonicwall_sample.exp", "stormshield", "sonicwall_to_stormshield.script"),
    ("sophos_sample.xml", "stormshield", "sophos_to_stormshield.script"),
    ("terraform_aws_sample.json", "stormshield", "terraform_aws_to_stormshield.script"),
    ("terraform_azure_sample.json", "stormshield", "terraform_azure_to_stormshield.script"),
    ("terraform_google_sample.json", "stormshield", "terraform_google_to_stormshield.script"),
    ("watchguard_sample.xml", "stormshield", "watchguard_to_stormshield.script"),
    ("ios_sample.cfg", "stormshield", "ios_to_stormshield.script"),
    ("huawei_sample.cfg", "stormshield", "huawei_to_stormshield.script"),
]


def test_detect_format() -> None:
    assert detect_format(b"\n  <?xml version='1.0'?><config/>") == "panos"
    assert detect_format(b"\xef\xbb\xbf<config/>") == "panos"
    assert detect_format(b"#config-version=FGT\nconfig system global\nend\n") == "fortios"
    assert detect_format(b"# Generated by iptables-save v1.8.9\n*filter\n") == "iptables"
    assert detect_format((DATA / "nftables_sample.nft").read_bytes()) == "nftables"
    assert detect_format((DATA / "nftables_sample.json").read_bytes()) == "nftables"
    assert detect_format((DATA / "nsx_sample.json").read_bytes()) == "nsx"
    assert detect_format((DATA / "aws_sample.json").read_bytes()) == "aws"
    assert detect_format((DATA / "azure_sample.json").read_bytes()) == "azure"
    assert detect_format((DATA / "routeros_sample.rsc").read_bytes()) == "routeros"
    assert detect_format((DATA / "opnsense_sample.xml").read_bytes()) == "opnsense"
    assert detect_format((DATA / "forcepoint_sample.json").read_bytes()) == "forcepoint"
    assert detect_format((DATA / "terraform_aws_sample.json").read_bytes()) == "terraform-aws"
    assert detect_format((DATA / "huawei_sample.cfg").read_bytes()) == "huawei"
    assert detect_format((DATA / "stormshield_sample.tgz").read_bytes()) == "stormshield"
    assert detect_format((DATA / "terraform_azure_sample.json").read_bytes()) == "terraform-azure"
    assert detect_format((DATA / "terraform_google_sample.json").read_bytes()) == "terraform-google"
    assert detect_format((DATA / "gcp_sample.json").read_bytes()) == "gcp"
    assert detect_format(b'\n[\n {"uid": "x", "rulebase": []}]') == "checkpoint"
    assert detect_format(b": Saved\n:\nASA Version 9.12(4)\n!\nhostname fw\n") == "asa"
    assert detect_format(b'<?xml version="1.0" encoding="UTF-8"?>\n<Configuration APIVersion="2000.1">') == "sophos"
    assert detect_format((DATA / "sophos_sample.xml").read_bytes()) == "sophos"
    assert detect_format((DATA / "fmc_sample.json").read_bytes()) == "fmc" and detect_format((DATA / "fdm_sample.txt").read_bytes()) == "fdm"
    assert detect_format((DATA / "checkpoint_sample.json").read_bytes()) == "checkpoint"
    assert detect_format(b'{"items": [{"type": "AccessRule", "name": "r"}], "paging": {"count": 1}}') == "fmc"
    assert detect_format(b'[{"type": "identitywrapper", "data": {"type": "accessrule", "name": "r"}}]') == "fdm"


@pytest.mark.parametrize("source,target,expected", CASES)
def test_golden_output(source: str, target: str, expected: str, tmp_path: Path) -> None:
    """The converted samples, byte for byte. Regenerate with FWSHIFT_UPDATE_GOLDEN=1 and review the diff."""
    out, report = tmp_path / "out", tmp_path / "report.txt"
    assert main(["convert", str(DATA / source), "--to", target, "-o", str(out), "--report", str(report), "-q"]) == 0
    golden_out, golden_report = GOLDEN / expected, GOLDEN / (expected + ".report.txt")
    written = out.read_text(encoding="utf-8")
    if target in ("fmc", "forcepoint"):
        # The script is the loader, which is a file of its own in the package, and then the policy: the policy is what is kept.
        head, marker, tail = written.partition("\n# The policy, as data.")
        assert head == (loader_source() if target == "fmc" else smc_loader_source()) and marker
        written = (marker.lstrip("\n") + tail).replace(f'"generator": "FWShift {__version__}"', '"generator": "FWShift (this version)"')
    if os.environ.get("FWSHIFT_UPDATE_GOLDEN"):
        GOLDEN.mkdir(exist_ok=True)
        golden_out.write_text(written, encoding="utf-8", newline="\n")
        golden_report.write_text(report.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    assert written == golden_out.read_text(encoding="utf-8")
    assert report.read_text(encoding="utf-8") == golden_report.read_text(encoding="utf-8")


def test_convert_writes_reports_and_strict_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out, text, data = tmp_path / "o.conf", tmp_path / "r.txt", tmp_path / "r.json"
    args = ["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "-o", str(out)]
    args += ["--report", str(text), "--report-json", str(data)]
    assert main(args) == 0
    assert "14 rules" in capsys.readouterr().err
    assert main(args + ["--strict", "-q"]) == 2  # the sample has rules that need review
    assert out.read_text(encoding="utf-8").startswith("# Generated by FWShift")
    assert "Security rules:" in text.read_text(encoding="utf-8")
    report = json.loads(data.read_text(encoding="utf-8"))
    assert report["summary"]["rule"]["total"] == 14
    by_name = {i["name"]: i for i in report["items"] if i["kind"] == "rule"}
    assert by_name["Admin-SSH"]["disabled"] is True and by_name["Admin-SSH"]["status"] == "needs-review"
    assert by_name["Block-OT-Outbound"]["status"] == "exact"


def test_stdout_output_and_maps(capsys: pytest.CaptureFixture[str]) -> None:
    args = ["convert", str(DATA / "fortios_sample.conf"), "--to", "panos", "-q"]
    args += ["--zone-map", "wan1=untrust", "--interface-map", "wan1=ethernet1/1", "--target-vsys", "vsys2"]
    args += ["--prune-unused"]
    assert main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert 'set vsys vsys2 rulebase security rules "LAN to Internet" to untrust' in captured.out
    assert "interface-address interface ethernet1/1" in captured.out
    assert "internal-all" not in captured.out  # unused group pruned


def test_app_map_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    app_map = tmp_path / "apps.json"
    app_map.write_text('{"bittorrent": ["tcp/6881-6889"]}', encoding="utf-8")
    assert main(["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "-q", "--app-map", str(app_map)]) == 0
    assert 'edit "app-bittorrent"' in capsys.readouterr().out
    app_map.write_text('{"bittorrent": ["nonsense"]}', encoding="utf-8")
    assert main(["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "-q", "--app-map", str(app_map)]) == 1
    assert "invalid port spec" in capsys.readouterr().err


def test_errors_are_reported_cleanly(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["convert", str(tmp_path / "missing.xml"), "--to", "fortios"]) == 1
    assert "cannot read" in capsys.readouterr().err
    assert main(["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "--vsys", "vsys9"]) == 1
    assert "vsys9" in capsys.readouterr().err
    assert main(["convert", str(DATA / "panos_sample.xml"), "--to", "fortios", "--zone-map", "broken"]) == 1
    assert "SOURCE=TARGET" in capsys.readouterr().err


def test_inspect(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["inspect", str(DATA / "fortios_sample.conf")]) == 0
    out = capsys.readouterr().out
    assert "format:          fortios" in out and "security rules:  14 (1 disabled)" in out
    assert "geo-blocked" in out


def test_manual_and_code_name_the_same_findings(tmp_path: Path) -> None:
    """Section 7 of the manual is the reference for finding codes: nothing in it is stale, nothing raised is missing."""
    root = Path(__file__).resolve().parents[1]
    manual = (root / "docs" / "MANUAL.md").read_text(encoding="utf-8")
    section = manual.split("## 7. Finding reference")[1].split("## 8. ")[0]
    documented = set(re.findall(r"`([A-Z][A-Z0-9_]{3,})`", section))
    source = "".join(path.read_text(encoding="utf-8") for path in (root / "src" / "fwshift").rglob("*.py"))
    stale = sorted(code for code in documented if f'"{code}"' not in source)
    assert not stale, stale
    raised = set()
    samples = sorted(path.name for path in DATA.iterdir() if path.is_file() and "_sample." in path.name and path.suffix != ".log")  # (logs, not configurations)
    assert len(samples) >= 13
    for sample in samples:
        for target in VENDORS:
            report = tmp_path / "report.json"
            args = ["convert", str(DATA / sample), "--to", target, "-o", str(tmp_path / "out"), "--report-json", str(report)]
            assert main(args + ["-q", "--prune-unused"]) == 0
            data = json.loads(report.read_text(encoding="utf-8"))
            raised |= {note["code"] for note in data["notes"]}
            raised |= {finding["code"] for item in data["items"] for finding in item["findings"]}
    assert len(raised) > 60  # the samples exercise most of the reference
    assert not sorted(raised - documented), sorted(raised - documented)


def test_version_is_the_same_everywhere_a_release_reads_it() -> None:
    """The release workflow takes the version from __init__.py and its text from the development log."""
    import fwshift

    root = Path(__file__).resolve().parents[1]
    version = fwshift.__version__
    assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
    # The line as the workflow reads it (sed: ^__version__ = "(.*)"$).
    lines = (root / "src" / "fwshift" / "__init__.py").read_text(encoding="utf-8").splitlines()
    assert [line for line in lines if re.fullmatch(r'__version__ = ".*"', line)] == [f'__version__ = "{version}"']
    log = (root / "DEVELOPMENT.md").read_text(encoding="utf-8")
    assert f"| Version | {version} (alpha) |" in log
    entry = [part for part in log.split("\n### ") if part.splitlines()[0].endswith(f": version {version}")]
    assert len(entry) == 1, "the development log needs one entry for this version"
    built = entry[0].split("**Built**", 1)[1].split("\n**", 1)[0]
    assert built.strip().startswith("* "), "what is listed under **Built** is the text of the release"
    short = version.rsplit(".", 1)[0]
    assert f"This manual covers version {short}." in (root / "docs" / "MANUAL.md").read_text(encoding="utf-8")
    assert f"**Status: alpha ({short}).**" in (root / "README.md").read_text(encoding="utf-8")
    # The guide, and every file name of the single-file package the documents give, say this version too.
    guide = (root / "docs" / "guide.html").read_text(encoding="utf-8")
    assert f"Field guide · version {short}" in guide
    for name in ("README.md", "docs/MANUAL.md", "docs/guide.html"):
        named = set(re.findall(r"fwshift-([0-9]+\.[0-9]+\.[0-9]+)\.pyz", (root / name).read_text(encoding="utf-8")))
        assert named <= {version}, (name, named)
    workflow = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "src/fwshift/__init__.py" in workflow and 's/^__version__ = "\\(.*\\)"$/\\1/p' in workflow


def test_inputs_larger_than_the_limit_are_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    big = tmp_path / "big.conf"
    big.write_bytes(b"#" * (1024 * 1024 + 1))
    monkeypatch.setenv("FWSHIFT_MAX_INPUT_MB", "1")
    assert main(["inspect", str(big)]) == 1
    assert "larger than 1 MiB" in capsys.readouterr().err
    monkeypatch.setenv("FWSHIFT_MAX_INPUT_MB", "zero")
    assert main(["inspect", str(big)]) == 1
    assert "FWSHIFT_MAX_INPUT_MB" in capsys.readouterr().err
