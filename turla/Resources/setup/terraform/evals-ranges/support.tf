#####################################################################################
# Create some VMs
# Linux - Support LAN
#####################################################################################

module "support-dns-srv1" {
  name                 = "${var.name-prefix}-support-dns-srv1"
  source               = "../modules/linuxsrv-latest-static"
  location             = var.location
  admin_username       = var.dev_linux_username
  admin_password       = var.dev_linux_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.support.id
  description          = "DNS Ubuntu Server"
  environment          = local.default_tags.environment
  static_ip_list       = tolist([var.support_dns_ip])
  ssh_private_key_path = var.ssh_private_key_path
  ssh_public_key_path  = var.ssh_public_key_path
  enable_ip_forwarding = true
  azure_vm_size        = local.azure-vm-size-small
}

module "support-jumpbox-srv1" {
  source         = "../modules/winsrv-latest-static"
  name           = "${var.name-prefix}-jumpbox-srv1"
  location       = var.location
  admin_username = var.win_srv_admin_username
  admin_password = var.win_srv_admin_password
  group_name     = module.rgroup.name
  subnet_id      = azurerm_subnet.red.id
  description    = "Support - Windows Jumpbox Server"
  environment    = local.default_tags.environment
  static_ip_list = tolist([var.red_jumpbox_ip])
  netbios_name   = var.red_jumpbox_hostname
}

#####################################################################################
# Create some VMs
# Linux - Red LAN
#####################################################################################

module "boltnet-redirect-srv1" {
  source               = "../modules/linuxsrv-latest-static"
  name                 = "${var.name-prefix}-redirect-srv1"
  admin_username       = var.dev_linux_username
  admin_password       = var.dev_linux_password
  location             = module.rgroup.location
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.boltnet.id
  description          = "Redirect Ubuntu Server - amalie"
  environment          = local.default_tags.environment
  static_ip_list       = var.carbon_support_c2_ip_list
  enable_ip_forwarding = true
  azure_vm_size        = local.azure-vm-size-small
  default_dns_servers  = module.support-dns-srv1.ips
  ssh_private_key_path = var.ssh_private_key_path
  ssh_public_key_path  = var.ssh_public_key_path
}

# Snake Redirector
module "boltnet-redirect-srv2" {
  source               = "../modules/linuxsrv-latest-static"
  name                 = "${var.name-prefix}-redirect-srv2"
  location             = module.rgroup.location
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.support.id
  description          = "Redirect Ubuntu Server - thunderbug"
  environment          = local.default_tags.environment
  static_ip_list       = var.snake_support_c2_ip_list
  enable_ip_forwarding = true
  azure_vm_size        = local.azure-vm-size-small
  admin_username       = var.dev_linux_username
  admin_password       = var.dev_linux_password
  default_dns_servers  = module.support-dns-srv1.ips
  ssh_private_key_path = var.ssh_private_key_path
  ssh_public_key_path  = var.ssh_public_key_path
}

module "boltnet-redirect-srv3" {
  source               = "../modules/linuxsrv-latest-static"
  name                 = "${var.name-prefix}-redirect-srv3"
  location             = module.rgroup.location
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.support.id
  description          = "Redirect Ubuntu Server - bolt"
  environment          = local.default_tags.environment
  static_ip_list       = var.snake_support_c2_ip_list_2
  enable_ip_forwarding = true
  azure_vm_size        = local.azure-vm-size-small
  admin_username       = var.dev_linux_username
  admin_password       = var.dev_linux_password
  default_dns_servers  = module.support-dns-srv1.ips
  ssh_private_key_path = var.ssh_private_key_path
  ssh_public_key_path  = var.ssh_public_key_path
}

module "support-pf-srv1" {
  name                 = "${var.name-prefix}-pf-srv1"
  source               = "../modules/linuxsrv-latest-static"
  location             = var.location
  admin_username       = var.dev_linux_username
  admin_password       = var.dev_linux_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.support.id
  description          = "Postfix Ubuntu Server"
  environment          = local.default_tags.environment
  static_ip_list       = tolist([var.support_postfix_ip])
  ssh_private_key_path = var.ssh_private_key_path
  ssh_public_key_path  = var.ssh_public_key_path
}

module "support-web-srv3" {
  name                 = "${var.name-prefix}-support-web-srv3"
  source               = "../modules/linuxsrv-latest-static"
  location             = var.location
  admin_username       = var.dev_linux_username
  admin_password       = var.dev_linux_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.support.id
  description          = "Web Ubuntu Server"
  environment          = local.default_tags.environment
  static_ip_list       = tolist([var.support_web_ip])
  ssh_private_key_path = var.ssh_private_key_path
  ssh_public_key_path  = var.ssh_public_key_path
  enable_ip_forwarding = true
  azure_vm_size        = local.azure-vm-size-small
  default_dns_servers  = module.support-dns-srv1.ips
}

module "red-kali1" {
  source               = "../modules/linuxsrv-latest-static"
  name                 = "${var.name-prefix}-kali-dev1"
  location             = var.location
  admin_username       = var.dev_linux_username
  admin_password       = var.dev_linux_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.red.id
  description          = "Kali Attack Platform VM"
  environment          = local.default_tags.environment
  static_ip_list       = var.red_kali_platform_ip_list
  ssh_private_key_path = var.ssh_private_key_path
  ssh_public_key_path  = var.ssh_public_key_path
  default_dns_servers  = module.support-dns-srv1.ips

}




