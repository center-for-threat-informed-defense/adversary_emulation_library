# Provided in case you wish to manage Terraform state in S3.
# Replace the suffix in the "bucket" attribute to a random value.
# See Terraform docs for overview of dynamodb and versioning, https://developer.hashicorp.com/terraform/language/settings/backends/s3.

#terraform {
#  backend "s3" {
#    bucket = "tfstate-${var.unique_prefix}-9d8ed57f5561d3ca51c40"
#    key    = "state/${var.unique_prefix}-tflotus.state"
#    region = var.region
#    # for aws, terraform locking is done via dynamodb (aws nosql db service)
#    # dynamodb must manually created with "LockID" as partition key (String type)
#    dynamodb_table = "${var.unique_prefix}-ocean-tfstate"
#  }
#}
