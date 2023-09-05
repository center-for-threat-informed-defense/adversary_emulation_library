
# Provision EC2 instances

## Security Groups
resource "aws_security_group" "oc-ssh-sg" {
  name        = "${var.unique_prefix}-oc-ssh-sg"
  description = "OceanLotus-${var.unique_prefix}: Allows SSH access to instance"
  vpc_id      = aws_vpc.oc-vpc.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ip-whitelist
  }
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
  tags = merge({ "Name" : "${var.unique_prefix} OceanLotus ssh sg" }, local.default_tags)
}

resource "aws_security_group" "oc-rdp-sg" {
  name        = "${var.unique_prefix}-oc-rdp-sg"
  description = "OceanLotus-${var.unique_prefix}: Allows rdp access to instance"
  vpc_id      = aws_vpc.oc-vpc.id
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.ip-whitelist
  }
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
  tags = merge({ "Name" : "${var.unique_prefix} OceanLotus rdp sg" }, local.default_tags)
}

resource "aws_security_group" "oc-winrm-sg" {
  name        = "${var.unique_prefix}-oc-winrm-sg"
  description = "OceanLotus-${var.unique_prefix}: Allows winrm access to instance"
  vpc_id      = aws_vpc.oc-vpc.id
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = var.ip-whitelist
  }
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
  tags = merge({ "Name" : "${var.unique_prefix} OceanLotus winrm sg" }, local.default_tags)
}


## Kali boxes
resource "aws_instance" "kali1" {
  ami                         = data.aws_ami.kali-ami.id
  instance_type               = local.aws-vm-size-medium
  key_name                    = aws_key_pair.oceanlotuskey.key_name
  subnet_id                   = aws_subnet.oc-pub-subnet-1.id
  vpc_security_group_ids      = [aws_security_group.oc-ssh-sg.id]
  private_ip                  = local.kali1-private-ip
  associate_public_ip_address = true
  lifecycle {
    ignore_changes = [
      ami
    ]
  }

  tags = merge({ "Name" : "${var.unique_prefix}-kali1" }, local.default_tags)
}

## Ubuntu
resource "aws_instance" "drogon" {
  ami                         = data.aws_ami.ubuntu-focal.id
  instance_type               = local.aws-vm-size-medium
  key_name                    = aws_key_pair.oceanlotuskey.key_name
  subnet_id                   = aws_subnet.oc-pub-subnet-1.id
  vpc_security_group_ids      = [aws_security_group.oc-ssh-sg.id]
  private_ip                  = local.drogon-private-ip
  associate_public_ip_address = true
  lifecycle {
    ignore_changes = [
      ami
    ]
  }

  tags = merge({ "Name" : "${var.unique_prefix}-drogon" }, local.default_tags)
}

## Windows Server
data "template_file" "user_data" {
  template = file("${path.module}/files/winrm.txt")
}

resource "aws_instance" "vhagar" {
  ami                         = data.aws_ami.windows-2019.id
  instance_type               = local.aws-vm-size-medium
  key_name                    = aws_key_pair.oceanlotuskey.key_name # aws only supports RSA keys for this attribute
  subnet_id                   = aws_subnet.oc-pub-subnet-1.id
  vpc_security_group_ids      = [aws_security_group.oc-ssh-sg.id, aws_security_group.oc-rdp-sg.id, aws_security_group.oc-winrm-sg.id]
  get_password_data           = true
  user_data_replace_on_change = false
  user_data                   = data.template_file.user_data.rendered
  private_ip                  = local.vhagar-private-ip
  associate_public_ip_address = true

  tags = merge({ "Name" : "${var.unique_prefix}-vhagar" }, local.default_tags)

  lifecycle {
    ignore_changes = [
      user_data,
      ami
    ]
  }
}

## Mac EC2 instance
### Mac dedicated host
resource "aws_ec2_host" "macos-host" {
  instance_type     = local.mac-ec2-host-type
  availability_zone = var.aws-region-az

  tags = merge({ "Name" : "${var.unique_prefix}-macos-host" }, local.default_tags)
}

### Mac instance
resource "aws_instance" "dreamfyre" {
  ami                         = data.aws_ami.mac-catalina.id
  host_id                     = aws_ec2_host.macos-host.id
  instance_type               = local.mac-ec2-host-type
  key_name                    = aws_key_pair.oceanlotuskey.key_name
  subnet_id                   = aws_subnet.oc-pub-subnet-1.id
  vpc_security_group_ids      = [aws_security_group.oc-ssh-sg.id]
  private_ip                  = local.dreamfyre-private-ip
  associate_public_ip_address = true

  tags = merge({ "Name" : "${var.unique_prefix}-dreamfyre" }, local.default_tags)
}
