#
#
#data "aws_vpc" "selected" {
#  id = local.mitre-vpc-id
#}
#
## Provision EC2 instances
### Kali boxes
#resource "aws_instance" "kali1" {
#  ami                    = local.kali-ami-id
#  instance_type          = local.aws-vm-size-medium
#  key_name               = aws_key_pair.ockey.key_name
#  subnet_id              = local.mitre-only-subnet-id
#  vpc_security_group_ids = [local.mitre-only-sg-default, local.mitre-only-sg-mitre-all, local.mitre-only-sg-mitre-baseline, local.mitre-only-sg-mitre-web, local.mitre-only-sg-git-access]
#
#  tags = merge({ "Name" : "kali1" }, local.default_tags)
#}
#
#resource "aws_instance" "kali2" {
#  ami                    = local.kali-ami-id
#  instance_type          = local.aws-vm-size-medium
#  key_name               = aws_key_pair.ockey.key_name
#  subnet_id              = local.mitre-only-subnet-id
#  vpc_security_group_ids = [local.mitre-only-sg-default, local.mitre-only-sg-mitre-all, local.mitre-only-sg-mitre-baseline, local.mitre-only-sg-mitre-web, local.mitre-only-sg-git-access]
#
#  tags = merge({ "Name" : "kali2" }, local.default_tags)
#}
#
### Ubuntu
#resource "aws_instance" "drogon" {
#  ami                    = data.aws_ami.ubuntu-focal.id
#  instance_type          = local.aws-vm-size-medium
#  key_name               = aws_key_pair.ockey.key_name
#  subnet_id              = local.mitre-only-subnet-id
#  vpc_security_group_ids = [local.mitre-only-sg-default, local.mitre-only-sg-mitre-all, local.mitre-only-sg-mitre-baseline, local.mitre-only-sg-mitre-web]
#  lifecycle {
#    ignore_changes = [
#      ami
#    ]
#  }
#
#  tags = merge({ "Name" : "drogon" }, local.default_tags)
#}
#
#resource "aws_instance" "seasmoke" {
#  ami                    = data.aws_ami.ubuntu-focal.id
#  instance_type          = local.aws-vm-size-medium
#  key_name               = aws_key_pair.ockey.key_name
#  subnet_id              = local.mitre-only-subnet-id
#  vpc_security_group_ids = [local.mitre-only-sg-default, local.mitre-only-sg-mitre-all, local.mitre-only-sg-mitre-baseline, local.mitre-only-sg-mitre-web]
#
#  tags = merge({ "Name" : "seasmoke" }, local.default_tags)
#}
#
#
### Windows Server
#data "template_file" "user_data" {
#  template = file("${path.module}/files/winrm.ps1")
#}
#resource "aws_instance" "vhagar" {
#  ami                         = data.aws_ami.windows-2019.id
#  instance_type               = local.aws-vm-size-medium
#  key_name                    = aws_key_pair.rsakey.key_name # because aws windows is special and only supports rsa
#  subnet_id                   = local.mitre-only-subnet-id
#  vpc_security_group_ids      = [local.mitre-only-sg-default, local.mitre-only-sg-mitre-all, local.mitre-only-sg-mitre-baseline, local.mitre-only-sg-mitre-web]
#  get_password_data           = true
#  user_data_replace_on_change = false
#  user_data                   = data.template_file.user_data.rendered
#
#  tags = merge({ "Name" : "vhagar" }, local.default_tags)
#
#  lifecycle {
#    ignore_changes = [
#      user_data,
#      ami
#    ]
#  }
#}
#
#resource "aws_instance" "caraxes" {
#  ami                    = data.aws_ami.fedora-38.id
#  instance_type          = local.aws-vm-size-medium
#  key_name               = aws_key_pair.rsakey.key_name
#  subnet_id              = local.mitre-only-subnet-id
#  vpc_security_group_ids = [local.mitre-only-sg-default, local.mitre-only-sg-mitre-all, local.mitre-only-sg-mitre-baseline, local.mitre-only-sg-mitre-web]
#
#  tags = merge({ "Name" : "caraxes" }, local.default_tags)
#}
