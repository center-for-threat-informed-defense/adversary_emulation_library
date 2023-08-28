# locals

locals {
  aws-vm-size-small  = "t3.medium"
  aws-vm-size-medium = "t3.large"
  aws-vm-size-large  = "t3.xlarge"

  # Mac instance type
  mac-ec2-host-type = "mac1.metal"

  default_tags = {
    region      = var.region
    description = "${var.unique_prefix}-oceanlotus"
    created_by  = "terraform"
  }

  drogon-private-ip    = "10.90.30.7"  # Ubuntu
  vhagar-private-ip    = "10.90.30.20" # Windows AD
  dreamfyre-private-ip = "10.90.30.22" # Mac
  kali1-private-ip     = "10.90.30.26" # Kali
}
