
#####################################################################################
# Create some VMs
# Windows - Victim LAN - Servers
#####################################################################################


module "snake-ad-srv1" {
  source                          = "../modules/winsrv-latest-static"
  name                            = "${var.name-prefix}-snake-ad-srv1"
  location                        = var.location
  admin_username                  = var.win_srv_admin_username
  admin_password                  = var.win_srv_admin_password
  group_name                      = module.rgroup.name
  subnet_id                       = azurerm_subnet.snake_srv_v2.id
  description                     = "Snake - Windows Server AD"
  environment                     = local.default_tags.environment
  active_directory_domain_name    = var.win_snake_domain_name
  active_directory_admin_password = var.win_srv_admin_username
  active_directory_admin_username = var.win_srv_admin_password
  source_image_sku                = var.snake_win_srv_os_azure_source_image_sku
  source_image_version            = var.snake_win_srv_os_azure_source_image_version
  static_ip_list                  = tolist([var.snake_srv_ad_ip])
  netbios_name                    = var.snake_srv_ad_hostname
}

module "snake-ex-srv1" {
  source                          = "../modules/winsrv-latest-static"
  name                            = "${var.name-prefix}-snake-ex-srv1"
  location                        = var.location
  admin_username                  = var.win_srv_admin_username
  admin_password                  = var.win_srv_admin_password
  group_name                      = module.rgroup.name
  subnet_id                       = azurerm_subnet.snake_srv_v2.id
  description                     = "Snake - Windows Exchange AD"
  environment                     = local.default_tags.environment
  active_directory_domain_name    = var.win_snake_domain_name
  active_directory_admin_password = var.win_srv_admin_username
  active_directory_admin_username = var.win_srv_admin_password
  source_image_sku                = var.snake_win_srv_os_azure_source_image_sku
  source_image_version            = var.snake_win_srv_os_azure_source_image_version
  static_ip_list                  = tolist([var.snake_srv_ex_ip])
  netbios_name                    = var.snake_srv_ex_hostname
}

module "snake-file-srv1" {
  source                          = "../modules/winsrv-latest-static"
  name                            = "${var.name-prefix}-snake-file-srv1"
  location                        = var.location
  admin_username                  = var.win_srv_admin_username
  admin_password                  = var.win_srv_admin_password
  group_name                      = module.rgroup.name
  subnet_id                       = azurerm_subnet.snake_srv_v2.id
  description                     = "Snake - Windows File Server"
  environment                     = local.default_tags.environment
  active_directory_domain_name    = var.win_snake_domain_name
  active_directory_admin_password = var.win_srv_admin_username
  active_directory_admin_username = var.win_srv_admin_password
  source_image_sku                = var.snake_win_srv_os_azure_source_image_sku
  source_image_version            = var.snake_win_srv_os_azure_source_image_version
  static_ip_list                  = tolist([var.snake_srv_file_ip])
  netbios_name                    = var.snake_srv_file_hostname
}


#####################################################################################
# Create some VMs
# Windows - Victim LAN - Desktops
#####################################################################################


module "snake-desk1" {
  source               = "../modules/windesk-latest-static"
  name                 = "${var.name-prefix}-snake-desk1"
  location             = var.location
  admin_username       = var.dev_win_admin_username
  admin_password       = var.dev_win_admin_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.snake_desk_v2.id
  description          = "Windows Desktop Victim VM on domain"
  environment          = local.default_tags.environment
  source_image_sku     = var.snake_win_desk_os_azure_source_image_sku
  source_image_version = var.snake_win_desk_os_azure_source_image_version
  static_ip_list       = tolist([var.snake_desk_1_ip])
  netbios_name         = var.snake_desk_1_hostname
}

module "snake-desk2" {
  source               = "../modules/windesk-latest-static"
  name                 = "${var.name-prefix}-snake-desk2"
  location             = var.location
  admin_username       = var.dev_win_admin_username
  admin_password       = var.dev_win_admin_password
  group_name           = module.rgroup.name
  subnet_id            = azurerm_subnet.snake_desk_v2.id
  description          = "Windows Desktop Victim VM on domain"
  environment          = local.default_tags.environment
  source_image_sku     = var.snake_win_desk_os_azure_source_image_sku
  source_image_version = var.snake_win_desk_os_azure_source_image_version
  static_ip_list       = tolist([var.snake_desk_2_ip])
  netbios_name         = var.snake_desk_2_hostname
}
