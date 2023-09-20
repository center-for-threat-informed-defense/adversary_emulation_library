variable "name" {
  type        = string
  description = "Base name of resource"
}

variable "location" {
  type        = string
  description = "Azure location for resource group"
}

variable "description" {
  type        = string
  description = "(Optional) Description tag of resource group"
  default     = ""
}

variable "environment" {
  type        = string
  description = "(Optional) Environment tag of resource group"
  default     = ""
}

variable "category" {
  type        = string
  description = "(Optional) Category of resource group, (similar to name, used for ansible automation)"
  default     = ""
}

variable "group_name" {
  type        = string
  description = "Resource group name to place VM"
}

variable "subnet_id" {
  type        = string
  description = "ID of subnet to place VM"
}

variable "admin_username" {
  type        = string
  description = "Admin username for VM"
  default     = "devadmin"
}

variable "admin_password" {
  type        = string
  description = "Admin password for VM"
}

variable "static_ip_list" {
  type        = list(string)
  description = "List of static IPs to assign to nics. NOTE: length of list will determine the number of NICs created. e.g., if you specify 3 IPs, then 3 NICs will be created."
}

variable "ssh_public_key_path" {
  type        = string
  description = "File path to SSH public key"
}

variable "ssh_private_key_path" {
  type        = string
  description = "File path to matching SSH private key"
}

variable "disk_storage_type" {
  type        = string
  description = "Disk speed of OS disk"
  default     = "StandardSSD_LRS"
}

variable "source_image_offer" {
  type        = string
  description = "Source image offer to use (Azure)"
  default     = "0001-com-ubuntu-server-focal"
}

variable "source_image_publisher" {
  type        = string
  description = "Publisher of OS image"
  default     = "Canonical"
}

variable "source_image_sku" {
  type        = string
  description = "SKU of OS image"
  default     = "20_04-lts-gen2"
}

variable "source_image_version" {
  type        = string
  description = "Version of OS image"
  default     = "20.04.202207130"
}

variable "azure_vm_size" {
  type        = string
  description = "Azure-specific VM size"
  default     = "Standard_D2s_v4"
}

variable "default_dns_servers" {
  type        = list(string)
  description = "DNS server to configure NIC. For Windows hosts on domain, should be set to domain controller. Setting to empty string will use vnet default."
  default     = null
}

variable "enable_ip_forwarding" {
  type        = bool
  description = "Whether to enable traffic forwarding within Azure"
  default     = true
}
