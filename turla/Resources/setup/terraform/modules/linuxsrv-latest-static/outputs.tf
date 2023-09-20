output "name" {
  value = var.name
}

output "ips" {
  description = "IP addresses provisioned."
  value       = azurerm_network_interface.main[*].private_ip_address
}
