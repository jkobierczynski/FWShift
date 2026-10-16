# FWShift lab, tier 1, Azure (lab/README.md): a resource group with a virtual network, a management subnet and one
# subnet per zone, and one small test host per lab address. Each host has two NICs: the management one (public
# address; its NSG lets SSH in from admin_cidr only) and the test one, without an NSG of its own: the converted NSG of
# its zone is associated with the subnet by lab/lab.py.

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
variable "vm_size" {
  type    = string
  default = "Standard_B1s" # two NICs
}
variable "zones" { type = map(string) }
variable "hosts" {
  type = map(object({ zone = string, ip = string, user_data = string }))
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false # the converted NSGs are made outside Terraform
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

resource "azurerm_network_security_group" "mgmt" {
  name                = "${var.run_id}-mgmt"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  security_rule {
    name                       = "ssh-from-admin"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.admin_cidr
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "nothing-out-to-the-internet"
    priority                   = 4000
    direction                  = "Outbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "Internet"
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
  size                            = var.vm_size
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

output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "vnet" {
  value = azurerm_virtual_network.lab.name
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
