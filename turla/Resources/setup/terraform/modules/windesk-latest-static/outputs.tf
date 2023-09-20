output "name" {
  value = azurerm_windows_virtual_machine.main.name
}

output "ips" {
  description = "IP addresses provisioned."
  value       = azurerm_network_interface.main[*].private_ip_address
}
