output "name" {
  value = var.name
}

output "location" {
  value = azurerm_resource_group.resource_group.location
}
