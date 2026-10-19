# FWShift lab, tier 3, Azure Marketplace (lab/README.md): one firewall image with a management NIC and one NIC in each
# zone subnet (address .4, the first Azure leaves to a subnet), and one small test host per lab address. Each zone
# subnet's route table sends the other zones to the firewall's NIC in it (a virtual appliance); the firewall's NICs
# forward. The test subnets have no NSG of their own: the firewall decides. Accept the image's terms once
# (az vm image terms accept --urn PUBLISHER:OFFER:PLAN:latest).

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.80" }
  }
}

variable "location" { type = string }
variable "run_id" { type = string }
variable "admin_cidr" { type = string }
variable "ssh_public_key" {
  type = string
  validation {
    condition     = startswith(var.ssh_public_key, "ssh-rsa ")
    error_message = "Azure takes only RSA keys for its VMs."
  }
}
variable "zones" { type = map(string) }
variable "zone_order" {
  type        = list(string)
  description = "the zones in the order of the firewall's data NICs"
}
variable "published" {
  type        = map(list(string))
  description = "addresses the firewall publishes (destination NAT), by zone: secondary addresses of its NIC there"
  default     = {}
}
variable "firewall_image" {
  type        = object({ publisher = string, offer = string, sku = string, version = string })
  description = "the Marketplace image; its plan is the same publisher, offer (product) and sku (name)"
}
variable "firewall_plan" {
  type    = bool
  default = true # (a Marketplace image is sold under a plan; a free one may have none)
}
variable "firewall_size" { type = string }
variable "firewall_user" {
  type    = string
  default = "fwlab"
}
variable "firewall_custom_data" {
  type    = string
  default = ""
}
variable "firewall_ports" {
  type        = list(number)
  description = "TCP ports of the firewall's management NIC open to admin_cidr"
  default     = [22, 443]
}
variable "host_size" {
  type    = string
  default = "Standard_B1s" # two NICs
}
variable "hosts" {
  type = map(object({ zone = string, ip = string, user_data = string }))
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

resource "azurerm_resource_group" "lab" {
  name     = var.run_id
  location = var.location
  tags     = { fwshift-lab = var.run_id }
}

resource "azurerm_virtual_network" "lab" {
  name                = var.run_id
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  address_space       = ["10.20.0.0/16"]
}

resource "azurerm_subnet" "mgmt" {
  name                 = "mgmt"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.20.250.0/24"]
}

resource "azurerm_subnet" "zone" {
  for_each             = var.zones
  name                 = each.key
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = [each.value]
}

# Management: the firewall's ports and SSH to the test hosts from the admin address, nothing else in.
resource "azurerm_network_security_group" "mgmt" {
  name                = "${var.run_id}-mgmt"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  security_rule {
    name                       = "admin-in"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = [for p in distinct(concat([22], var.firewall_ports)) : tostring(p)]
    source_address_prefix      = var.admin_cidr
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "nothing-else-in"
    priority                   = 4000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "mgmt" {
  subnet_id                 = azurerm_subnet.mgmt.id
  network_security_group_id = azurerm_network_security_group.mgmt.id
}

# Each zone's other zones through the firewall's NIC in it.
resource "azurerm_route_table" "zone" {
  for_each            = var.zones
  name                = "${var.run_id}-${each.key}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  dynamic "route" {
    for_each = { for other, cidr in var.zones : other => cidr if other != each.key }
    content {
      name                   = "to-${route.key}"
      address_prefix         = route.value
      next_hop_type          = "VirtualAppliance"
      next_hop_in_ip_address = cidrhost(var.zones[each.key], 4)
    }
  }
}

resource "azurerm_subnet_route_table_association" "zone" {
  for_each       = var.zones
  subnet_id      = azurerm_subnet.zone[each.key].id
  route_table_id = azurerm_route_table.zone[each.key].id
}

resource "azurerm_public_ip" "fw" {
  name                = "${var.run_id}-fw"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "fw_mgmt" {
  name                = "${var.run_id}-fw-mgmt"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  ip_configuration {
    name                          = "mgmt"
    subnet_id                     = azurerm_subnet.mgmt.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.20.250.4"
    public_ip_address_id          = azurerm_public_ip.fw.id
    primary                       = true
  }
}

# .4 the primary address, then the addresses the firewall publishes in the zone.
resource "azurerm_network_interface" "fw_zone" {
  for_each                      = var.zones
  name                          = "${var.run_id}-fw-${each.key}"
  resource_group_name           = azurerm_resource_group.lab.name
  location                      = azurerm_resource_group.lab.location
  enable_ip_forwarding          = true
  enable_accelerated_networking = false
  dynamic "ip_configuration" {
    for_each = { for index, ip in concat([cidrhost(each.value, 4)], lookup(var.published, each.key, [])) : index => ip }
    content {
      name                          = "ip${ip_configuration.key}"
      subnet_id                     = azurerm_subnet.zone[each.key].id
      private_ip_address_allocation = "Static"
      private_ip_address            = ip_configuration.value
      primary                       = ip_configuration.key == 0
    }
  }
}

resource "azurerm_linux_virtual_machine" "firewall" {
  name                            = "${var.run_id}-firewall"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  size                            = var.firewall_size
  admin_username                  = var.firewall_user
  disable_password_authentication = true
  network_interface_ids           = concat([azurerm_network_interface.fw_mgmt.id], [for zone in var.zone_order : azurerm_network_interface.fw_zone[zone].id])
  custom_data                     = var.firewall_custom_data != "" ? base64encode(var.firewall_custom_data) : null
  boot_diagnostics {} # (its serial console, kept in console.txt when it does not come up)
  admin_ssh_key {
    username   = var.firewall_user
    public_key = var.ssh_public_key
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = var.firewall_image.publisher
    offer     = var.firewall_image.offer
    sku       = var.firewall_image.sku
    version   = var.firewall_image.version
  }
  dynamic "plan" {
    for_each = var.firewall_plan ? [1] : []
    content {
      publisher = var.firewall_image.publisher
      product   = var.firewall_image.offer
      name      = var.firewall_image.sku
    }
  }
}

resource "azurerm_public_ip" "host" {
  for_each            = var.hosts
  name                = "${var.run_id}-${each.key}"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  allocation_method   = "Static"
  sku                 = "Standard"
}

resource "azurerm_network_interface" "mgmt" {
  for_each            = var.hosts
  name                = "${var.run_id}-${each.key}-mgmt"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  ip_configuration {
    name                          = "mgmt"
    subnet_id                     = azurerm_subnet.mgmt.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.host[each.key].id
    primary                       = true
  }
}

resource "azurerm_network_interface" "test" {
  for_each            = var.hosts
  name                = "${var.run_id}-${each.key}-test"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  ip_configuration {
    name                          = "test"
    subnet_id                     = azurerm_subnet.zone[each.value.zone].id
    private_ip_address_allocation = "Static"
    private_ip_address            = each.value.ip
  }
}

resource "azurerm_linux_virtual_machine" "host" {
  for_each                        = var.hosts
  name                            = "${var.run_id}-${each.key}"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  size                            = var.host_size
  admin_username                  = "azureuser"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.mgmt[each.key].id, azurerm_network_interface.test[each.key].id]
  custom_data                     = base64encode(each.value.user_data)
  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

output "firewall_ip" {
  value = azurerm_public_ip.fw.ip_address
}

output "firewall_instance" {
  value = azurerm_linux_virtual_machine.firewall.virtual_machine_id
}

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "user" {
  value = "azureuser"
}

output "hosts" {
  value = {
    for name, host in var.hosts : name => {
      mgmt_ip = azurerm_public_ip.host[name].ip_address
      test_ip = host.ip
    }
  }
}
