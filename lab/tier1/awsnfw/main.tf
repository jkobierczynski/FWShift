# FWShift lab, tier 1, AWS Network Firewall (lab/README.md, 0.41.7): a VPC with a management subnet, one subnet per
# zone and a subnet for the firewall's endpoint, and one small test host per lab address. Each host has two interfaces:
# the management one (public address, SSH from admin_cidr only) and the test one in its zone's subnet, whose security
# group lets everything through, so that the firewall decides. lab/lab.py applies this twice: first the network and
# the hosts; then, once FWShift's script has made the firewall policy, the firewall with that policy and the routes
# that send each zone's traffic to the other zones through its endpoint (routes more specific than the VPC's own).

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

variable "region" { type = string }
variable "run_id" { type = string }
variable "admin_cidr" { type = string }
variable "ssh_public_key" { type = string }
variable "instance_type" {
  type    = string
  default = "t3.micro" # two network interfaces
}
variable "zones" { type = map(string) }
variable "hosts" {
  type = map(object({ zone = string, ip = string, user_data = string }))
}
variable "firewall_policy_arn" {
  type        = string
  description = "the policy FWShift's script made; empty for the first apply (no firewall yet)"
  default     = ""
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { fwshift-lab = var.run_id }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}

locals {
  az       = data.aws_availability_zones.available.names[0]
  firewall = var.firewall_policy_arn != ""
  # The endpoint of the firewall in the one zone of the lab, once it exists.
  endpoint = local.firewall ? one(flatten([
    for state in aws_networkfirewall_firewall.lab[0].firewall_status[0].sync_states : [for a in state.attachment : a.endpoint_id]
  ])) : ""
}

resource "aws_vpc" "lab" {
  cidr_block = "10.20.0.0/16"
  tags       = { Name = var.run_id }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
}

resource "aws_subnet" "mgmt" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.20.250.0/24"
  availability_zone = local.az
  tags              = { Name = "${var.run_id}-mgmt" }
}

resource "aws_route_table" "mgmt" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
}

resource "aws_route_table_association" "mgmt" {
  subnet_id      = aws_subnet.mgmt.id
  route_table_id = aws_route_table.mgmt.id
}

resource "aws_subnet" "zone" {
  for_each          = var.zones
  vpc_id            = aws_vpc.lab.id
  cidr_block        = each.value
  availability_zone = local.az
  tags              = { Name = "${var.run_id}-${each.key}" }
}

# The firewall's endpoint has a subnet of its own; what it lets through goes on by the VPC's local route.
resource "aws_subnet" "firewall" {
  vpc_id            = aws_vpc.lab.id
  cidr_block        = "10.20.240.0/28"
  availability_zone = local.az
  tags              = { Name = "${var.run_id}-firewall" }
}

resource "aws_networkfirewall_firewall" "lab" {
  count               = local.firewall ? 1 : 0
  name                = var.run_id
  description         = "FWShift lab: the converted policy"
  firewall_policy_arn = var.firewall_policy_arn
  vpc_id              = aws_vpc.lab.id
  delete_protection   = false
  subnet_mapping {
    subnet_id = aws_subnet.firewall.id
  }
}

# Each zone sends the other zones to the endpoint (both ways, so that the firewall sees both halves of a connection);
# before the firewall exists, the table has the VPC's local route only.
resource "aws_route_table" "zone" {
  for_each = var.zones
  vpc_id   = aws_vpc.lab.id
  dynamic "route" {
    for_each = local.firewall ? { for other, cidr in var.zones : other => cidr if other != each.key } : {}
    content {
      cidr_block      = route.value
      vpc_endpoint_id = local.endpoint
    }
  }
  tags = { Name = "${var.run_id}-${each.key}" }
}

resource "aws_route_table_association" "zone" {
  for_each       = var.zones
  subnet_id      = aws_subnet.zone[each.key].id
  route_table_id = aws_route_table.zone[each.key].id
}

# SSH from the address the run is managed from, nothing else.
resource "aws_security_group" "mgmt" {
  name        = "${var.run_id}-mgmt"
  description = "FWShift lab: SSH from the admin address"
  vpc_id      = aws_vpc.lab.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  egress = []
}

# The test interfaces: everything of the lab through, so that the firewall decides.
resource "aws_security_group" "open" {
  name        = "${var.run_id}-open"
  description = "FWShift lab: all lab traffic, the firewall decides"
  vpc_id      = aws_vpc.lab.id
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.20.0.0/16"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_key_pair" "lab" {
  key_name   = var.run_id
  public_key = var.ssh_public_key
}

resource "aws_network_interface" "test" {
  for_each        = var.hosts
  subnet_id       = aws_subnet.zone[each.value.zone].id
  private_ips     = [each.value.ip]
  security_groups = [aws_security_group.open.id]
  tags            = { Name = "${var.run_id}-${each.key}-test" }
}

resource "aws_instance" "host" {
  for_each                    = var.hosts
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  key_name                    = aws_key_pair.lab.key_name
  subnet_id                   = aws_subnet.mgmt.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.mgmt.id]
  user_data                   = each.value.user_data
  user_data_replace_on_change = true
  tags                        = { Name = "${var.run_id}-${each.key}" }
}

resource "aws_network_interface_attachment" "test" {
  for_each             = var.hosts
  instance_id          = aws_instance.host[each.key].id
  network_interface_id = aws_network_interface.test[each.key].id
  device_index         = 1
}

output "vpc_id" {
  value = aws_vpc.lab.id
}

output "endpoint" {
  value = local.endpoint
}

output "user" {
  value = "ec2-user"
}

output "hosts" {
  value = {
    for name, host in var.hosts : name => {
      mgmt_ip   = aws_instance.host[name].public_ip
      test_ip   = host.ip
      interface = aws_network_interface.test[name].id
    }
  }
}
