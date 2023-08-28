# macOS AMI images
## Get latest Apple macOS Monterey 12 AMI
data "aws_ami" "mac-monterrey" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn-ec2-macos-12*"]
  }
}
## Get latest Apple macOS Big Sur 11 AMI
data "aws_ami" "mac-bigsur" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn-ec2-macos-11*"]
  }
}
## Get latest Apple macOS Catalina 10.5 AMI
data "aws_ami" "mac-catalina" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn-ec2-macos-10.15*"]
  }
}
## Get latest Apple macOS Mojave 10.4 AMI
data "aws_ami" "mac-mojave" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn-ec2-macos-10.14*"]
  }
}

# Windows Server Images
## Get latest Windows Server 2019 AMI
data "aws_ami" "windows-2019" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base*"]
  }
}

# Ubuntu Images
## Get latest Ubuntu 20.04 (Focal)
data "aws_ami" "ubuntu-focal" {
  most_recent = true
  owners      = ["099720109477"] # Canonical (posted on Ubuntu official docs, https://help.ubuntu.com/community/EC2StartersGuide)
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  # add filter for hvm virtualization type (vs pv)
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_ami" "fedora-38" {
  most_recent = true
  owners      = ["125523088429"] # Fedora (correlated by looking up owner of AMIs listed on official Fedora site, https://alt.fedoraproject.org/cloud/)
  filter {
    name   = "name"
    values = ["Fedora-Cloud-Base-38-1.*gp*"]
  }
  # add filter for arch
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  # add filter for hvm virt type
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_ami" "kali-ami" {
  most_recent = true
  owners      = ["679593333241"] # Kali Organization (correlated by looking up owner of AMIs via process referenced by Kali, https://www.kali.org/docs/cloud/aws/)
  # add filter for name
  filter {
    name   = "name"
    values = ["kali-*2023*"]
  }
  # add filter for arch
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
  # add filter for hvm virt type
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

}
