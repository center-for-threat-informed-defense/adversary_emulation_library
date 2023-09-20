# Terraform variables
variable "location" {
  type        = string
  description = "Azure location/region for resources"
}

variable "name-prefix" {
  type        = string
  description = "String prefix for resource names"
}

#####################################################################################
# networking
#####################################################################################

variable "vnet1-address-space" {
  type        = string
  description = "vnet 1 address space"
  default     = "10.20.0.0/16"
}

variable "vnet1-address-space-2" {
  type        = string
  description = "Additional address range for vnet1"
  default     = "10.100.0.0/16"
}

variable "vnet1-sub1-range" {
  type        = string
  description = "IP range of subnet 1 on vnet 1 (must be within vnet 1 address space)"
  default     = "10.20.10.0/24"
}

variable "vnet1-sub2-range" {
  type        = string
  description = "IP range of subnet 2 on vnet 1 (must be within vnet 1 address space)"
  default     = "10.20.20.0/24"
}

variable "vnet1-sub3-range" {
  type        = string
  description = "IP range of subnet 3 on vnet 1 (must be within vnet 1 address space)"
  default     = "10.100.30.0/24"
}

variable "vnet1-sub4-range" {
  type        = string
  description = "IP range of subnet 4 on vnet 1 (must be within vnet 1 address space)"
  default     = "10.100.40.0/24"
}

variable "vnet1-sub5-range" {
  type        = string
  description = "IP range of subnet 5 on vnet 1 (must be within vnet 1 address space)"
  default     = "10.20.50.0/24"
}

variable "vnet1-sub6-range" {
  type        = string
  description = "IP range of subnet 5 on vnet 1 (must be within vnet 1 address space)"
  default     = "10.20.60.0/24"
}


variable "vnet2-address-space" {
  type        = string
  description = "vnet 2 address space"
  default     = "176.59.0.0/16"
}

variable "vnet2-sub1-range" {
  type        = string
  description = "IP range of subnet (must be within vnet 2 address space)"
  default     = "176.59.15.0/24"
}

variable "vnet3-address-space" {
  type        = string
  description = "vnet 3 address space"
  default     = "91.52.0.0/16"
}

variable "vnet3-sub1-range" {
  type        = string
  description = "IP range of subnet on vnet 3 (must be within vnet 3 address space)"
  default     = "91.52.62.0/24"
}

variable "vnet3-sub2-range" {
  type        = string
  description = "IP range of subnet on vnet 3 (must be within vnet 3 address space)"
  default     = "91.52.201.0/24"
}

#####################################################################################
# default credentials
#####################################################################################

variable "dev_win_admin_username" {
  type        = string
  description = "Username for Windows 10 desktop dev boxes"
  default     = "devadmin"
}

variable "dev_win_admin_password" {
  type        = string
  description = "Password for Windows 10 desktop dev boxes"
}

variable "dev_linux_username" {
  type        = string
  description = "Username for Linux hosts"
}

variable "dev_linux_password" {
  type        = string
  description = "Password for dev Linux hosts"
}

variable "win_srv_admin_username" {
  type        = string
  description = "Windows Server admin username"
}

variable "win_srv_admin_password" {
  type        = string
  description = "Windows server admin password"
}

variable "win_domain_name" {
  type        = string
  description = "Domain name for AD"
}

variable "win_netbios_name" {
  type        = string
  description = "Netbios name for AD"
}

#####################################################################################
# VM configuration
# IP addresses
#####################################################################################

variable "carbon_support_c2_ip_list" {
  type        = list(string)
  description = "IPs to be assigned to C2"
  default     = ["91.52.62.64", "91.52.62.137", "91.52.62.203"]
}

variable "snake_support_c2_ip_list" {
  type        = list(string)
  description = "IPs to be assigned to C2"
  default     = ["91.52.201.31", "91.52.201.98", "91.52.201.119"]
}

variable "snake_support_c2_ip_list_2" {
  type        = list(string)
  description = "IPs to be assigned to C2"
  default     = ["91.52.201.144", "91.52.201.202"]
}

variable "red_kali_platform_ip_list" {
  type    = list(string)
  default = ["176.59.15.33", "176.59.15.44"]
}

variable "red_jumpbox_ip" {
  type    = string
  default = "176.59.15.13"
}

variable "detlab_srv_ip" {
  type    = string
  default = "176.59.15.55"
}

variable "carbon_srv_ad_ip" {
  type    = string
  default = "10.20.10.9"
}

variable "carbon_srv_ex_ip" {
  type    = string
  default = "10.20.10.17"
}

variable "carbon_srv_web_ip" {
  type    = string
  default = "10.20.10.23"
}

variable "carbon_desk_1_ip" {
  type    = string
  default = "10.20.20.102"
}

variable "carbon_desk_2_ip" {
  type    = string
  default = "10.20.20.103"
}

variable "carbon_desk_3_ip" {
  type    = string
  default = "10.20.20.104"
}

variable "snake_srv_ad_ip" {
  type    = string
  default = "10.100.30.202"
}

variable "snake_srv_ex_ip" {
  type    = string
  default = "10.100.30.203"
}

variable "snake_srv_file_ip" {
  type    = string
  default = "10.100.30.204"
}

variable "snake_desk_1_ip" {
  type    = string
  default = "10.100.40.102"
}

variable "snake_desk_2_ip" {
  type    = string
  default = "10.100.40.103"
}

variable "support_web_ip" {
  type    = string
  default = "91.52.201.21"
}

variable "support_dns_ip" {
  type    = string
  default = "91.52.201.22"
}

variable "support_postfix_ip" {
  type    = string
  default = "91.52.201.29"
}
#####################################################################################
# VM configuration
# ad/exchange
#####################################################################################

variable "win_carbon_domain_name" {
  type        = string
  description = "Domain name for Carbon"
  default     = "skt.local"
}

variable "win_snake_domain_name" {
  type        = string
  description = "Domain name for Snake"
  default     = "nk.local"
}

variable "win_carbon_netbios_name" {
  type        = string
  description = "Netbios name for Carbon"
  default     = "skt"
}

variable "win_snake_netbios_name" {
  type        = string
  description = "Netbios name for Snake"
  default     = "nk"
}

#####################################################################################
# VM configuration
# OS versions
#####################################################################################

# Carbon
variable "carbon_win_srv_os_azure_source_image_sku" {
  type        = string
  description = "Sku for Windows Server to use (Carbon)"
  default     = "2019-datacenter"
}

variable "carbon_win_srv_os_azure_source_image_version" {
  type        = string
  description = "Version for Windows Server to use (Carbon)"
  default     = "2019.0.20190410"
}

variable "carbon_win_ad_srv_os_azure_source_image_sku" {
  type        = string
  description = "Sku for Windows Server to use (Carbon AD server only)"
  default     = "2019-datacenter"
}

variable "carbon_win_ad_srv_os_azure_source_image_version" {
  type        = string
  description = "Version for Windows Server to use (Carbon AD server only)"
  default     = "17763.3406.220909"
}

variable "carbon_win_desk_os_azure_source_image_sku" {
  type        = string
  description = "Sku for Windows Server to use (Carbon)"
  default     = "win10-21h2-pro-g2"
}

variable "carbon_win_desk_os_azure_source_image_version" {
  type        = string
  description = "Version for Windows Server to use (Carbon)"
  default     = "19044.2006.220909"
}

# Snake
variable "snake_win_srv_os_azure_source_image_sku" {
  type        = string
  description = "Sku for Windows Server to use (snake)"
  default     = "2019-datacenter"
}

variable "snake_win_srv_os_azure_source_image_version" {
  type        = string
  description = "Version for Windows Server to use (snake)"
  default     = "17763.3406.220909"
}

variable "snake_win_desk_os_azure_source_image_sku" {
  type        = string
  description = "Sku for Windows Server to use (snake)"
  default     = "19h1-pro-gensecond"
}

variable "snake_win_desk_os_azure_source_image_version" {
  type        = string
  description = "Version for Windows Server to use (snake)"
  default     = "18362.1256.2012032308"
}

#####################################################################################
# VM configuration
# hostnames
#####################################################################################

variable "red_kali_platform_hostname" {
  type    = string
  default = "modin"
}

variable "red_postfix_hostname" {
  type    = string
  default = "richards"
}

variable "red_web_hostname" {
  type    = string
  default = "clymer"
}

variable "detlab_srv_hostname" {
  type        = string
  description = "Detlab hostname"
  default     = "kontos"
}

variable "support_dns_hostname" {
  type    = string
  default = "stlouis"
}

variable "carbon_srv_ad_hostname" {
  type    = string
  default = "bannik"
}

variable "carbon_srv_ex_hostname" {
  type    = string
  default = "brieftragerin"
}

variable "carbon_srv_web_hostname" {
  type    = string
  default = "kagarov"
}

variable "carbon_desk_1_hostname" {
  type    = string
  default = "hobgoblin"
}

variable "carbon_desk_2_hostname" {
  type    = string
  default = "domovoy"
}

variable "carbon_desk_3_hostname" {
  type    = string
  default = "khabibulin"
}

variable "snake_srv_ad_hostname" {
  type    = string
  default = "berlios"
}

variable "snake_srv_ex_hostname" {
  type    = string
  default = "drebule"
}

variable "snake_srv_file_hostname" {
  type    = string
  default = "berzas"
}

variable "snake_desk_1_hostname" {
  type    = string
  default = "uosis"
}

variable "snake_desk_2_hostname" {
  type    = string
  default = "azuolas"
}

variable "red_jumpbox_hostname" {
  type    = string
  default = "stelio"
}

# SSH keys for linux systems
variable "ssh_public_key_path" {
  type        = string
  description = "Path to SSH public key to use for Linux ssh systems (public and private key must be matching pair)"
}

variable "ssh_private_key_path" {
  type        = string
  description = "Path to SSH private key to use for Linux ssh systems (public and private key must be matching pair)"
}
