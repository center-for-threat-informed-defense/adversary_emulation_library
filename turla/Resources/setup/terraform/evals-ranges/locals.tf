locals {
  ##################################################################################################################
  # Common settings to avoid repeating strings throughout configuration
  ##################################################################################################################
  azure-vm-size-small  = "Standard_D2s_v4"
  azure-vm-size-medium = "Standard_D4s_v4"
  azure-vm-size-large  = "Standard_D8s_v4"

  slow-disk      = "Standard_LRS"
  fast-disk      = "StandardSSD_LRS"
  very-fast-disk = "Premium_LRS"
}