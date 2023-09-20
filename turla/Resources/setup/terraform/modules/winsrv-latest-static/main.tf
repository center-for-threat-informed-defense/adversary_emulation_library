
# locals
locals {
  default_tags = {
    region      = var.location
    description = tostring(try(var.description))
    category    = tostring(try(var.category))
    environment = tostring(try(var.environment))
  }
}


# create a nic
resource "azurerm_network_interface" "main" {
  count                = length(var.static_ip_list)
  name                 = "${var.name}-nic-${count.index}"
  location             = var.location
  resource_group_name  = var.group_name
  enable_ip_forwarding = var.enable_ip_forwarding
  dns_servers          = var.default_dns_servers

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Static"
    private_ip_address            = var.static_ip_list[count.index]
    public_ip_address_id          = var.public_ip_address_id
  }
}

resource "azurerm_windows_virtual_machine" "main" {
  name                     = var.name
  computer_name            = local.computer_name
  location                 = var.location
  resource_group_name      = var.group_name
  size                     = var.azure_vm_size
  admin_username           = var.admin_username
  admin_password           = var.admin_password
  patch_mode               = "Manual"
  enable_automatic_updates = false
  custom_data              = local.custom_data
  network_interface_ids    = azurerm_network_interface.main[*].id

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = var.source_image_sku
    version   = var.source_image_version
  }
  os_disk {
    storage_account_type = var.disk_storage_type
    caching              = "ReadWrite"
    disk_size_gb         = var.disk_size
  }
  additional_unattend_content {
    content = local.auto_logon_data
    setting = "AutoLogon"
  }

  additional_unattend_content {
    content = local.first_logon_data
    setting = "FirstLogonCommands"
  }

  lifecycle {
    ignore_changes = [
      tags,
      enable_automatic_updates,
      source_image_id,
      source_image_reference,
      os_disk,
      patch_mode,
      zone,
      size,
      name,
      network_interface_ids
    ]
  }

  tags = local.default_tags


}
