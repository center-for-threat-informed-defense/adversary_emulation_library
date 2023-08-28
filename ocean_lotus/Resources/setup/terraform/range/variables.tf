variable "aws-profile" {
  type        = string
  description = "REQUIRED: AWS Profile to use with Terraform"
}

variable "region" {
  type        = string
  description = "AWS region to use, defaults to us-east-1"
  default     = "us-east-1"
}

variable "aws-region-az" {
  type        = string
  description = "AWS availability zone to use, defaults to us-east-1a"
  default     = "us-east-1a"
}

variable "oceanlotus-public-key-file" {
  type        = string
  description = "Path to OceanLotus generated SSH public key (must be of type RSA)"
  default     = "../../oceanlotus.pub"
}

variable "oceanlotus-private-key-file" {
  type        = string
  description = "Path to OceanLotus generated SSH private key (must be of type RSA)"
  default     = "../../oceanlotus"
}

variable "unique_prefix" {
  type        = string
  description = "REQUIRED: Unique prefix to use when naming resources"
}

variable "ip-whitelist" {
  type        = list(string)
  description = "REQUIRED: List of public IP(s) to whitelist access to resources. For example, to whitelist the IP 172.16.1.5, the value of ip-whitelist would be: [\"172.16.1.5/32\"]"
}
