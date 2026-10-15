# FWShift lab, tier 1, Google Cloud (lab/README.md): two VPC networks, one for management (SSH from admin_cidr
# only) and one for the tests with a subnet per zone, and one small test host per lab address with a NIC in each.
# The converted network firewall policy is associated with the test network by lab/lab.py; that network lets the
# policy decide before any VPC firewall rule, and has none.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = { source = "hashicorp/google", version = ">= 5.0, < 7.0" }
  }
}

variable "project" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "run_id" { type = string }
variable "admin_cidr" { type = string }
variable "ssh_public_key" { type = string }
variable "machine_type" {
  type    = string
  default = "e2-small" # two NICs
}
variable "zones" { type = map(string) }
variable "hosts" {
  type = map(object({ zone = string, ip = string, user_data = string }))
}

provider "google" {
  project = var.project
  region  = var.region
}

resource "google_compute_network" "mgmt" {
  name                    = "${var.run_id}-mgmt"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "mgmt" {
  name          = "${var.run_id}-mgmt"
  network       = google_compute_network.mgmt.id
  region        = var.region
  ip_cidr_range = "10.21.250.0/24"
}

resource "google_compute_firewall" "mgmt_ssh" {
  name          = "${var.run_id}-mgmt-ssh"
  network       = google_compute_network.mgmt.id
  direction     = "INGRESS"
  source_ranges = [var.admin_cidr]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# Nothing out of the management network but the replies of SSH (the metadata server is not behind it).
resource "google_compute_firewall" "mgmt_no_egress" {
  name               = "${var.run_id}-mgmt-no-egress"
  network            = google_compute_network.mgmt.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "all"
  }
}

resource "google_compute_network" "test" {
  name                                      = "${var.run_id}-test"
  auto_create_subnetworks                   = false
  network_firewall_policy_enforcement_order = "BEFORE_CLASSIC_FIREWALL"
}

resource "google_compute_subnetwork" "zone" {
  for_each      = var.zones
  name          = "${var.run_id}-${each.key}"
  network       = google_compute_network.test.id
  region        = var.region
  ip_cidr_range = each.value
}

resource "google_compute_instance" "host" {
  for_each     = var.hosts
  name         = "${var.run_id}-${each.key}"
  machine_type = var.machine_type
  zone         = var.zone
  labels       = { fwshift-lab = var.run_id }
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }
  network_interface {
    subnetwork = google_compute_subnetwork.mgmt.id
    access_config {}
  }
  network_interface {
    subnetwork = google_compute_subnetwork.zone[each.value.zone].id
    network_ip = each.value.ip
  }
  metadata = {
    enable-oslogin = "FALSE"
    ssh-keys       = "lab:${var.ssh_public_key}"
  }
  metadata_startup_script = each.value.user_data
}

output "test_network" {
  value = google_compute_network.test.name
}

output "user" {
  value = "lab"
}

output "hosts" {
  value = {
    for name, host in var.hosts : name => {
      mgmt_ip = google_compute_instance.host[name].network_interface[0].access_config[0].nat_ip
      test_ip = host.ip
    }
  }
}
