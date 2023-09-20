
resource "random_id" "id-random" {
  byte_length = 3
}

# Data source references to the current subscription.
data "azurerm_subscription" "current" {}
data "azurerm_client_config" "current" {}

# locals
locals {
  default_tags = {
    region      = var.location
    environment = "YOUR_RANGE_ENV"
  }
}

# main

## resource group
module "rgroup" {
  source   = "../modules/rgroup"
  name     = "${var.name-prefix}-rg"
  location = var.location
}

#####################################################################################
# Networking
#####################################################################################
## setup networking - company lan
### 1 vnet, 4 subnets
resource "azurerm_virtual_network" "vnet1" {
  name                = "${var.name-prefix}-vnet1"
  address_space       = [var.vnet1-address-space, var.vnet1-address-space-2]
  location            = module.rgroup.location
  resource_group_name = module.rgroup.name
  tags                = local.default_tags
}

resource "azurerm_subnet" "carbon_srv" {
  name                 = "${var.name-prefix}-carbon-srv"
  resource_group_name  = module.rgroup.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = [var.vnet1-sub1-range]
}

resource "azurerm_subnet" "carbon_desk" {
  name                 = "${var.name-prefix}-carbon-desk"
  resource_group_name  = module.rgroup.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = [var.vnet1-sub2-range]
}

resource "azurerm_subnet" "snake_srv_v2" {
  name                 = "${var.name-prefix}-snake-srv-v2"
  resource_group_name  = module.rgroup.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = [var.vnet1-sub3-range]
}

resource "azurerm_subnet" "snake_desk_v2" {
  name                 = "${var.name-prefix}-snake-desk-v2"
  resource_group_name  = module.rgroup.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = [var.vnet1-sub4-range]
}

## Setup networking - red/support lan
### 1 vnet, 2 subnet
resource "azurerm_virtual_network" "vnet2" {
  name                = "${var.name-prefix}-vnet2"
  address_space       = [var.vnet2-address-space]
  location            = module.rgroup.location
  resource_group_name = module.rgroup.name

  tags = local.default_tags
}

resource "azurerm_subnet" "red" {
  name                 = "${var.name-prefix}-red"
  resource_group_name  = module.rgroup.name
  virtual_network_name = azurerm_virtual_network.vnet2.name
  address_prefixes     = [var.vnet2-sub1-range]
}

resource "azurerm_virtual_network" "vnet3" {
  name                = "${var.name-prefix}-vnet3"
  location            = module.rgroup.location
  resource_group_name = module.rgroup.name
  address_space       = [var.vnet3-address-space]
}

resource "azurerm_subnet" "boltnet" {
  name                 = "${var.name-prefix}-boltnet"
  resource_group_name  = module.rgroup.name
  virtual_network_name = azurerm_virtual_network.vnet3.name
  address_prefixes     = [var.vnet3-sub1-range]
}

resource "azurerm_subnet" "support" {
  name                 = "${var.name-prefix}-support"
  resource_group_name  = module.rgroup.name
  virtual_network_name = azurerm_virtual_network.vnet3.name
  address_prefixes     = [var.vnet3-sub2-range]
}

# setup peering between vnets
resource "azurerm_virtual_network_peering" "peer1to2" {
  name                         = "${var.name-prefix}-peervic2support"
  resource_group_name          = module.rgroup.name
  virtual_network_name         = azurerm_virtual_network.vnet1.name
  remote_virtual_network_id    = azurerm_virtual_network.vnet2.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
  use_remote_gateways          = false
}

resource "azurerm_virtual_network_peering" "peer2to1" {
  name                         = "${var.name-prefix}-peersupport2vic"
  resource_group_name          = module.rgroup.name
  virtual_network_name         = azurerm_virtual_network.vnet2.name
  remote_virtual_network_id    = azurerm_virtual_network.vnet1.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = true
  # depends_on block needed because gateway in vnet1 is not created until after vpn gateway
  # therefore, this peer relationship, which requires a gateway to exist in vnet1, cannot be created
  # until after the vpn gateway is created.
  # Any peerXto1 relationships peering to vnet1 have the same dependency
  depends_on = [azurerm_virtual_network_gateway.main]
}

resource "azurerm_virtual_network_peering" "peer3to1" {
  name                         = "${var.name-prefix}-peerboltnet2vic"
  resource_group_name          = module.rgroup.name
  virtual_network_name         = azurerm_virtual_network.vnet3.name
  remote_virtual_network_id    = azurerm_virtual_network.vnet1.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = true
  # See comments in peer2to1 for more details on why depends_on is required
  depends_on = [azurerm_virtual_network_gateway.main]
}

resource "azurerm_virtual_network_peering" "peer1to3" {
  name                         = "${var.name-prefix}-peervic2boltnet"
  resource_group_name          = module.rgroup.name
  virtual_network_name         = azurerm_virtual_network.vnet1.name
  remote_virtual_network_id    = azurerm_virtual_network.vnet3.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = true
  use_remote_gateways          = false
}

resource "azurerm_virtual_network_peering" "peer2to3" {
  name                         = "${var.name-prefix}-peersupport2boltnet"
  resource_group_name          = module.rgroup.name
  virtual_network_name         = azurerm_virtual_network.vnet2.name
  remote_virtual_network_id    = azurerm_virtual_network.vnet3.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}

resource "azurerm_virtual_network_peering" "peer3to2" {
  name                         = "${var.name-prefix}-peerboltnet2support"
  resource_group_name          = module.rgroup.name
  virtual_network_name         = azurerm_virtual_network.vnet3.name
  remote_virtual_network_id    = azurerm_virtual_network.vnet2.id
  allow_virtual_network_access = true
  allow_forwarded_traffic      = true
  allow_gateway_transit        = false
  use_remote_gateways          = false
}



#####################################################################################
# VPN
#####################################################################################
# create vpn dependencies - public connection ip and subnet with name GatewaySubnet (exact name required)

# IP used as public connection point for clients
resource "azurerm_public_ip" "main" {
  name                = "${var.name-prefix}-pip"
  location            = module.rgroup.location
  resource_group_name = module.rgroup.name
  allocation_method   = "Dynamic"

  tags = local.default_tags
}

# name is **required** to literally be GatewaySubnet
# attach to vnet1
resource "azurerm_subnet" "vpn" {
  name                 = "GatewaySubnet"
  resource_group_name  = module.rgroup.name
  virtual_network_name = azurerm_virtual_network.vnet1.name
  address_prefixes     = [var.vnet1-sub5-range]
}

# create VPN
resource "azurerm_virtual_network_gateway" "main" {
  name                = "${var.name-prefix}-vpn"
  location            = module.rgroup.location
  resource_group_name = module.rgroup.name

  type     = "Vpn"
  vpn_type = "RouteBased"

  active_active = false
  enable_bgp    = false
  sku           = "VpnGw2"
  generation    = "Generation2"

  ip_configuration {
    name                          = "vnetGatewayConfig"
    public_ip_address_id          = azurerm_public_ip.main.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.vpn.id
  }

  custom_route {
    address_prefixes = [var.vnet2-address-space, var.vnet3-address-space]
  }

  vpn_client_configuration {
    address_space = ["10.1.0.0/24"]
  }
  tags = local.default_tags
}

