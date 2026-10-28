# FWShift lab, tier 3, AWS Marketplace (lab/README.md): one firewall image with a management interface and one
# interface in each zone subnet (address .4), and one small test host per lab address. The test hosts route the other
# zones through the firewall's interface in their own subnet; the security groups of the test subnets let all lab
# traffic through, so that the firewall decides. Subscribe to the image in the Marketplace console first (once).

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
variable "zones" { type = map(string) }
variable "zone_order" {
  type        = list(string)
  description = "the zones in the order of the firewall's data interfaces"
}
variable "firewall_ami" { type = string }
variable "firewall_instance_type" { type = string }
variable "firewall_user_data" {
  type    = string
  default = ""
}
variable "published" {
  type        = map(list(string))
  description = "addresses the firewall publishes (destination NAT), by zone: secondary addresses of its interface there"
  default     = {}
}
variable "firewall_ports" {
  type        = list(number)
  description = "TCP ports of the firewall's management interface open to admin_cidr"
  default     = [22, 443]
}
variable "mgmt_device_index" {
  type        = number
  description = "the device index of the management interface; the zones take the others, in zone_order (Sophos: 1, its WAN port)"
  default     = 0
}
variable "firewall_secrets" {
  type        = map(string)
  sensitive   = true
  description = "secrets the firewall reads from Secrets Manager at first boot, named RUN_ID-KEY (Sophos: its admin password)"
  default     = {}
}
variable "require_imdsv2" {
  type    = bool
  default = false
}
variable "host_instance_type" {
  type    = string
  default = "t3.micro"
}
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

resource "aws_security_group" "admin" {
  name        = "${var.run_id}-admin"
  description = "FWShift lab: management from the admin address"
  vpc_id      = aws_vpc.lab.id
  dynamic "ingress" {
    for_each = toset(var.firewall_ports)
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = [var.admin_cidr]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # (licence checks and updates of the image)
  }
}

resource "aws_security_group" "hostmgmt" {
  name        = "${var.run_id}-hostmgmt"
  description = "FWShift lab: SSH to the test hosts from the admin address"
  vpc_id      = aws_vpc.lab.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  egress = []
}

# The lab traffic itself: the firewall decides it, not a security group.
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

resource "aws_network_interface" "fw_mgmt" {
  subnet_id       = aws_subnet.mgmt.id
  security_groups = [aws_security_group.admin.id]
  tags            = { Name = "${var.run_id}-fw-mgmt" }
}

# .4 first (the primary address, which the firewall takes by DHCP), then the addresses it publishes in the zone: the VPC
# delivers those to this interface as well.
resource "aws_network_interface" "fw_zone" {
  for_each                = var.zones
  subnet_id               = aws_subnet.zone[each.key].id
  private_ip_list_enabled = true
  private_ip_list         = concat([cidrhost(each.value, 4)], lookup(var.published, each.key, []))
  security_groups   = [aws_security_group.open.id]
  source_dest_check = false
  tags              = { Name = "${var.run_id}-fw-${each.key}" }
}

# Attached once the instance runs: attached to its interface while the instance was still being made, AWS refused it
# (IncorrectInstanceState, "pending-instance-creation", the first pfSense run); Terraform waits for "running".
resource "aws_eip" "fw" {
  domain            = "vpc"
  network_interface = aws_network_interface.fw_mgmt.id
  depends_on        = [aws_internet_gateway.lab, aws_instance.firewall]
}

# The VPC delivers by destination, whatever next hop a host chose: each zone subnet sends the other zones to the
# firewall's interface in it (routes more specific than the VPC's own, one per subnet).
resource "aws_route_table" "zone" {
  for_each = var.zones
  vpc_id   = aws_vpc.lab.id
  dynamic "route" {
    for_each = { for other, cidr in var.zones : other => cidr if other != each.key }
    content {
      cidr_block           = route.value
      network_interface_id = aws_network_interface.fw_zone[each.key].id
    }
  }
  tags = { Name = "${var.run_id}-${each.key}" }
}

resource "aws_route_table_association" "zone" {
  for_each       = var.zones
  subnet_id      = aws_subnet.zone[each.key].id
  route_table_id = aws_route_table.zone[each.key].id
}

# Secrets the firewall reads at first boot (Sophos: the admin password, which its first-boot data names, not holds),
# deleted at once with the run (no recovery window), and a role that may read them and nothing else.
resource "aws_secretsmanager_secret" "fw" {
  for_each                = nonsensitive(toset(keys(var.firewall_secrets)))
  name                    = "${var.run_id}-${each.key}"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "fw" {
  for_each      = nonsensitive(toset(keys(var.firewall_secrets)))
  secret_id     = aws_secretsmanager_secret.fw[each.key].id
  secret_string = var.firewall_secrets[each.key]
}

resource "aws_iam_role" "fw" {
  count = local.has_secrets ? 1 : 0
  name  = "${var.run_id}-firewall"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "fw" {
  count = local.has_secrets ? 1 : 0
  name  = "secrets"
  role  = aws_iam_role.fw[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = [for secret in aws_secretsmanager_secret.fw : secret.arn]
    }]
  })
}

resource "aws_iam_instance_profile" "fw" {
  count = local.has_secrets ? 1 : 0
  name  = "${var.run_id}-firewall"
  role  = aws_iam_role.fw[0].name
}

locals {
  has_secrets = nonsensitive(length(var.firewall_secrets) > 0)
  # The device index of each zone's interface: the zones in zone_order, around the management interface.
  zone_index = { for index, zone in var.zone_order : zone => (index < var.mgmt_device_index ? index : index + 1) }
}

resource "aws_instance" "firewall" {
  ami                  = var.firewall_ami
  instance_type        = var.firewall_instance_type
  key_name             = aws_key_pair.lab.key_name
  user_data            = var.firewall_user_data != "" ? var.firewall_user_data : null
  iam_instance_profile = local.has_secrets ? aws_iam_instance_profile.fw[0].name : null
  network_interface {
    network_interface_id = aws_network_interface.fw_mgmt.id
    device_index         = var.mgmt_device_index
  }
  dynamic "network_interface" {
    for_each = local.zone_index
    content {
      network_interface_id = aws_network_interface.fw_zone[network_interface.key].id
      device_index         = network_interface.value
    }
  }
  dynamic "metadata_options" {
    for_each = var.require_imdsv2 ? [1] : []
    content {
      http_tokens   = "required"
      http_endpoint = "enabled"
    }
  }
  depends_on = [aws_secretsmanager_secret_version.fw, aws_iam_role_policy.fw]
  tags       = { Name = "${var.run_id}-firewall" }
}

resource "aws_network_interface" "test" {
  for_each        = var.hosts
  subnet_id       = aws_subnet.zone[each.value.zone].id
  private_ips     = [each.value.ip]
  security_groups = [aws_security_group.open.id]
}

resource "aws_instance" "host" {
  for_each                    = var.hosts
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.host_instance_type
  key_name                    = aws_key_pair.lab.key_name
  subnet_id                   = aws_subnet.mgmt.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.hostmgmt.id]
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

output "firewall_ip" {
  value = aws_eip.fw.public_ip
}

output "firewall_instance" {
  value = aws_instance.firewall.id
}

output "user" {
  value = "ec2-user"
}

output "hosts" {
  value = {
    for name, host in var.hosts : name => {
      mgmt_ip = aws_instance.host[name].public_ip
      test_ip = host.ip
    }
  }
}
