# Parent VPC
resource "aws_vpc" "oc-vpc" {
  cidr_block           = "10.90.30.0/24"
  enable_dns_hostnames = true
  tags                 = merge({ "Name" : "${var.unique_prefix} OceanLotus VPC" }, local.default_tags)

}
# Internet Gateway
resource "aws_internet_gateway" "oc-igw" {
  vpc_id = aws_vpc.oc-vpc.id
  tags   = merge({ "Name" : "${var.unique_prefix} OceanLotus IG" }, local.default_tags)
}

# Public Subnets
resource "aws_subnet" "oc-pub-subnet-1" {
  availability_zone = var.aws-region-az
  cidr_block        = "10.90.30.0/27"
  vpc_id            = aws_vpc.oc-vpc.id
  tags              = merge({ "Name" : "${var.unique_prefix} OceanLotus Pub Subnet 1" }, local.default_tags)
}

# Route Table for Public Subnets
resource "aws_route_table" "oc-pub-subnet-rt" {
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.oc-igw.id
  }
  vpc_id = aws_vpc.oc-vpc.id
  tags   = merge({ "Name" : "${var.unique_prefix} OceanLotus Route Table for Public Subnets" }, local.default_tags)
}

# RT to Subnets Assoc
resource "aws_route_table_association" "oc-pub-subnet-1-ra" {
  subnet_id      = aws_subnet.oc-pub-subnet-1.id
  route_table_id = aws_route_table.oc-pub-subnet-rt.id
}
