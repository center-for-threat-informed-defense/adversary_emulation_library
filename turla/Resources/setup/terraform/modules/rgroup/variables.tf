variable "name" {
  type        = string
  description = "Name of resource group"
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
  description = "(Optional) Category of resource group"
  default     = ""
}

variable "charge_code" {
  type        = string
  description = "(Optional) Charge code for billing, if used by your org"
  default     = ""
}
