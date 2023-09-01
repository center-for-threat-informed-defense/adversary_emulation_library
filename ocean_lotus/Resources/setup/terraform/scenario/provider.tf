# Define AWS provider
provider "aws" {
  region  = var.region
  profile = var.aws-profile
}
