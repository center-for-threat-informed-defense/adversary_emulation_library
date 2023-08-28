#resource "aws_ec2_host" "macos-host" {
#  instance_type     = local.mac-ec2-host-type
#  availability_zone = var.aws-region-az
#
#  tags = merge({ "Name" : "macos-host" }, local.default_tags)
#}
#
## Create the EC2 Instance
#resource "aws_instance" "dreamfyre" {
#  ami           = data.aws_ami.mac-catalina.id
#  host_id       = aws_ec2_host.macos-host.id
#  instance_type = local.mac-ec2-host-type
#  key_name      = aws_key_pair.ockey.key_name
#
#  subnet_id              = local.mitre-only-subnet-id
#  vpc_security_group_ids = [local.mitre-only-sg-default, local.mitre-only-sg-mitre-all, local.mitre-only-sg-mitre-baseline, local.mitre-only-sg-mitre-web]
#
#  tags = merge({ "Name" : "dreamfyre" }, local.default_tags)
#}
