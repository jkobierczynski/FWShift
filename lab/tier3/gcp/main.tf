# FWShift lab, tier 3, Google Cloud Marketplace (lab/README.md): one firewall image with a NIC in each of four VPC
# networks (Google Cloud puts every NIC of an instance in a network of its own): management, and one per zone (address
# .4); one small test host per lab address with a NIC in the management network and one in its zone's. Each zone's
# network sends the other zones to the firewall's NIC in it; the firewall forwards (can_ip_forward). The zone networks
# let all lab traffic in: the firewall decides. The image comes from its publisher's project, as its Marketplace
# listing names it.

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
variable "zones" { type = map(string) }
variable "zone_order" {
  type        = list(string)
  description = "the zones in the order of the firewall's data NICs"
}
variable "published" {
  type        = map(list(string))
  description = "addresses the firewall publishes (destination NAT), by zone: alias addresses of its NIC there"
  default     = {}
}
variable "firewall_image" { type = string }
variable "firewall_machine_type" { type = string }
variable "firewall_user" {
  type    = string
  default = "fwlab"
}
variable "firewall_metadata" {
  type        = map(string)
  description = "the image's first-boot metadata (user-data, startup-script, ...), beside ssh-keys"
  default     = {}
}
variable "firewall_ports" {
  type        = list(number)
  description = "TCP ports of the firewall's management NIC open to admin_cidr"
  default     = [22, 443]
}
variable "host_machine_type" {
  type    = string
  default = "e2-small" # two NICs
}
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
  ip_cidr_range = "10.20.250.0/24"
}

resource "google_compute_firewall" "mgmt_admin" {
  name          = "${var.run_id}-mgmt-admin"
  network       = google_compute_network.mgmt.id
  direction     = "INGRESS"
  source_ranges = [var.admin_cidr]
  allow {
    protocol = "tcp"
    ports    = [for p in distinct(concat([22], var.firewall_ports)) : tostring(p)]
  }
}

resource "google_compute_network" "zone" {
  for_each                = var.zones
  name                    = "${var.run_id}-${each.key}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "zone" {
  for_each      = var.zones
  name          = "${var.run_id}-${each.key}"
  network       = google_compute_network.zone[each.key].id
  region        = var.region
  ip_cidr_range = each.value
}

# The lab traffic itself: the firewall decides it, not a VPC firewall rule.
resource "google_compute_firewall" "zone_open" {
  for_each      = var.zones
  name          = "${var.run_id}-${each.key}-open"
  network       = google_compute_network.zone[each.key].id
  direction     = "INGRESS"
  source_ranges = ["10.20.0.0/16"]
  allow {
    protocol = "all"
  }
}

# Each zone's other zones through the firewall's NIC in it.
resource "google_compute_route" "zone" {
  for_each = { for pair in flatten([for zone, cidr in var.zones : [for other, ocidr in var.zones : { key = "${zone}-${other}", zone = zone, dest = ocidr } if other != zone]]) : pair.key => pair }
  name        = "${var.run_id}-${each.key}"
  network     = google_compute_network.zone[each.value.zone].id
  dest_range  = each.value.dest
  next_hop_ip = cidrhost(var.zones[each.value.zone], 4)
  priority    = 100
  depends_on  = [google_compute_instance.firewall]
}

resource "google_compute_address" "fw" {
  name   = "${var.run_id}-fw"
  region = var.region
}

resource "google_compute_instance" "firewall" {
  name           = "${var.run_id}-firewall"
  machine_type   = var.firewall_machine_type
  zone           = var.zone
  can_ip_forward = true
  labels         = { fwshift-lab = var.run_id }
  boot_disk {
    initialize_params {
      image = var.firewall_image
    }
  }
  network_interface {
    subnetwork = google_compute_subnetwork.mgmt.id
    network_ip = "10.20.250.4"
    access_config {
      nat_ip = google_compute_address.fw.address
    }
  }
  dynamic "network_interface" {
    for_each = var.zone_order
    content {
      subnetwork = google_compute_subnetwork.zone[network_interface.value].id
      network_ip = cidrhost(var.zones[network_interface.value], 4)
      dynamic "alias_ip_range" {
        for_each = lookup(var.published, network_interface.value, [])
        content {
          ip_cidr_range = "${alias_ip_range.value}/32"
        }
      }
    }
  }
  metadata = merge(var.firewall_metadata, {
    ssh-keys = "${var.firewall_user}:${var.ssh_public_key}"
  })
}

resource "google_compute_instance" "host" {
  for_each     = var.hosts
  name         = "${var.run_id}-${each.key}"
  machine_type = var.host_machine_type
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

output "firewall_ip" {
  value = google_compute_address.fw.address
}

output "firewall_instance" {
  value = google_compute_instance.firewall.instance_id
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
