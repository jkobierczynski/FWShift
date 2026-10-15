# FWShift lab, tier 1, AWS (lab/README.md): a VPC with a management subnet and one subnet per zone, and one small
# test host per lab address. Each host has two interfaces: the management one (public address, SSH from admin_cidr
# only, no outbound rule) and the test one, whose security groups are the converted policy. lab/lab.py runs this,
# loads the converted security groups, attaches them, probes and destroys everything.

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
  az = data.aws_availability_zones.available.names[0]
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

# SSH from the address the run is managed from, nothing else; no outbound rule (replies pass, being stateful).
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

# The group the test interfaces have before the converted groups are attached, and again before they are deleted.
resource "aws_security_group" "hold" {
  name        = "${var.run_id}-hold"
  description = "FWShift lab: nothing in, nothing out"
  vpc_id      = aws_vpc.lab.id
  egress      = []
}

resource "aws_key_pair" "lab" {
  key_name   = var.run_id
  public_key = var.ssh_public_key
}

resource "aws_network_interface" "test" {
  for_each        = var.hosts
  subnet_id       = aws_subnet.zone[each.value.zone].id
  private_ips     = [each.value.ip]
  security_groups = [aws_security_group.hold.id]
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

output "hold_group" {
  value = aws_security_group.hold.id
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
