#####################################################################################
# Create some VMs
# Windows - Victim LAN - Servers
#####################################################################################

#### AD Servers
module "carbon-ad-srv1" {
  source                          = "../modules/winsrv-latest-static"
  name                            = "${var.name-prefix}-carbon-ad-srv1"
  location                        = var.location
  admin_username                  = var.win_srv_admin_username
  admin_password                  = var.win_srv_admin_password
  group_name                      = module.rgroup.name
  subnet_id                       = azurerm_subnet.carbon_srv.id
  description                     = "Carbon - Windows Server AD"
  environment                     = local.default_tags.environment
  active_directory_domain_name    = var.win_carbon_domain_name
  active_directory_admin_password = var.win_srv_admin_username
  active_directory_admin_username = var.win_srv_admin_password
  static_ip_list                  = tolist([var.carbon_srv_ad_ip])
  source_image_sku                = var.carbon_win_srv_os_azure_source_image_sku
  source_image_version            = var.carbon_win_srv_os_azure_source_image_version
  netbios_name                    = var.carbon_srv_ad_hostname
}

#### Exchange server
module "carbon-ex-srv1" {
  name                            = "${var.name-prefix}-carbon-ex-srv1"
  source                          = "../modules/winsrv-latest-static"
  active_directory_admin_username = var.win_srv_admin_username
  active_directory_admin_password = var.win_srv_admin_password
  active_directory_domain_name    = var.win_snake_domain_name
  admin_username                  = var.dev_win_admin_username
  admin_password                  = var.dev_win_admin_password
  group_name                      = module.rgroup.name
  location                        = var.location
  subnet_id                       = azurerm_subnet.carbon_srv.id
  description                     = "Carbon - Windows Exchange Server"
  environment                     = local.default_tags.environment
  static_ip_list                  = tolist([var.carbon_srv_ex_ip])
  source_image_sku                = var.carbon_win_srv_os_azure_source_image_sku
  source_image_version            = var.carbon_win_srv_os_azure_source_image_version
  netbios_name                    = var.carbon_srv_ex_hostname
}

module "carbon-web-srv1" {
  name                 = "${var.name-prefix}-carbon-web-srv1"
  source               = "../modules/linuxsrv-latest-static"
  location             = var.location
  admin_username       = var.dev_linux_username
  admin_password       = var.dev_linux_password
  group_name           = module.rgroup.name
  description          = "Internal Web Server"
  environment          = local.default_tags.environment
  static_ip_list       = tolist([var.carbon_srv_web_ip])
  ssh_private_key_path = var.ssh_private_key_path
  ssh_public_key_path  = var.ssh_public_key_path
  subnet_id            = azurerm_subnet.carbon_srv.id
}


#####################################################################################
# Create some VMs
# Windows - Victim LAN - Desktops
#####################################################################################

module "carbon-desk1" {
  source               = "../modules/windesk-latest-static"
  name                 = "${var.name-prefix}-carbon-desk1"
  location             = var.location
  admin_username       = var.dev_win_admin_username
  admin_password       = var.dev_win_admin_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.carbon_desk.id
  description          = "Windows Desktop Victim VM on domain"
  environment          = local.default_tags.environment
  source_image_sku     = var.carbon_win_desk_os_azure_source_image_sku
  source_image_version = var.carbon_win_desk_os_azure_source_image_version
  static_ip_list       = tolist([var.carbon_desk_1_ip])
  netbios_name         = var.carbon_desk_1_hostname
}

module "carbon-desk2" {
  source               = "../modules/windesk-latest-static"
  name                 = "${var.name-prefix}-carbon-desk2"
  location             = var.location
  admin_username       = var.dev_win_admin_username
  admin_password       = var.dev_win_admin_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.carbon_desk.id
  description          = "Windows Desktop Victim VM on domain"
  environment          = local.default_tags.environment
  source_image_sku     = var.carbon_win_desk_os_azure_source_image_sku
  source_image_version = var.carbon_win_desk_os_azure_source_image_version
  static_ip_list       = tolist([var.carbon_desk_2_ip])
  netbios_name         = var.carbon_desk_2_hostname
}

module "carbon-desk3" {
  source               = "../modules/windesk-latest-static"
  name                 = "${var.name-prefix}-carbon-desk3"
  location             = var.location
  admin_username       = var.dev_win_admin_username
  admin_password       = var.dev_win_admin_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.carbon_desk.id
  description          = "Windows Desktop Victim VM on domain"
  environment          = local.default_tags.environment
  source_image_sku     = var.carbon_win_desk_os_azure_source_image_sku
  source_image_version = var.carbon_win_desk_os_azure_source_image_version
  static_ip_list       = tolist([var.carbon_desk_3_ip])
  netbios_name         = var.carbon_desk_3_hostname
}
