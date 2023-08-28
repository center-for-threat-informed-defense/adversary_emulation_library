
resource "aws_key_pair" "oceanlotuskey" {
  key_name   = "${var.unique_prefix}-oceanlotus"
  public_key = file(var.oceanlotus-public-key-file)
}
