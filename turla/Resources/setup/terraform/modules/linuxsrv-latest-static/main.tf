
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
  }
}

resource "azurerm_linux_virtual_machine" "main" {
  name                = var.name
  location            = var.location
  resource_group_name = var.group_name
  size                = var.azure_vm_size
  admin_username      = var.admin_username
  admin_password      = var.admin_password
  admin_ssh_key {
    public_key = file(var.ssh_public_key_path)
    username   = var.admin_username
  }
  disable_password_authentication = false
  network_interface_ids           = azurerm_network_interface.main[*].id

  source_image_reference {
    offer     = var.source_image_offer
    publisher = var.source_image_publisher
    sku       = var.source_image_sku
    version   = var.source_image_version
  }

  os_disk {
    storage_account_type = var.disk_storage_type
    caching              = "ReadWrite"
  }

  tags = local.default_tags
}
