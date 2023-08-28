<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 5.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 5.10.0 |
| <a name="provider_template"></a> [template](#provider\_template) | 2.2.0 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_ec2_host.macos-host](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_host) | resource |
| [aws_instance.dreamfyre](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance) | resource |
| [aws_instance.drogon](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance) | resource |
| [aws_instance.kali1](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance) | resource |
| [aws_instance.vhagar](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance) | resource |
| [aws_internet_gateway.oc-igw](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/internet_gateway) | resource |
| [aws_key_pair.oceanlotuskey](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/key_pair) | resource |
| [aws_route_table.oc-pub-subnet-rt](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table) | resource |
| [aws_route_table_association.oc-pub-subnet-1-ra](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association) | resource |
| [aws_route_table_association.oc-pub-subnet-2-ra](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association) | resource |
| [aws_security_group.oc-ssh-sg](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_subnet.oc-pub-subnet-1](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_subnet.oc-pub-subnet-2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_vpc.oc-vpc](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc) | resource |
| [aws_ami.fedora-38](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.kali-ami](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.mac-bigsur](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.mac-catalina](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.mac-mojave](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.mac-monterrey](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.ubuntu-focal](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.windows-2019](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [template_file.user_data](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_aws-profile"></a> [aws-profile](#input\_aws-profile) | REQUIRED: AWS Profile to use with Terraform | `string` | n/a | yes |
| <a name="input_aws-region-az"></a> [aws-region-az](#input\_aws-region-az) | AWS availability zone to use, defaults to us-east-1a | `string` | `"us-east-1a"` | no |
| <a name="input_ip-whitelist"></a> [ip-whitelist](#input\_ip-whitelist) | REQUIRED: List of public IP(s) to whitelist access to resources. For example, to whitelist the IP 172.16.1.5, the value of ip-whitelist would be: ["172.16.1.5/32"] | `list(string)` | n/a | yes |
| <a name="input_oceanlotus-private-key-file"></a> [oceanlotus-private-key-file](#input\_oceanlotus-private-key-file) | Path to OceanLotus generated SSH private key (must be of type RSA) | `string` | `"../../oceanlotus"` | no |
| <a name="input_oceanlotus-public-key-file"></a> [oceanlotus-public-key-file](#input\_oceanlotus-public-key-file) | Path to OceanLotus generated SSH public key (must be of type RSA) | `string` | `"../../oceanlotus.pub"` | no |
| <a name="input_region"></a> [region](#input\_region) | AWS region to use, defaults to us-east-1 | `string` | `"us-east-1"` | no |
| <a name="input_unique_prefix"></a> [unique\_prefix](#input\_unique\_prefix) | REQUIRED: Unique prefix to use when naming resources | `string` | n/a | yes |

## Outputs

No outputs.
<!-- END_TF_DOCS -->
