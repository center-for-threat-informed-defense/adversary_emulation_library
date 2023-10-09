output "vhagar_windows_ad_ip" {
  value = aws_instance.vhagar.public_ip
}
output "dreamfyre_mac_ip" {
  value = aws_instance.dreamfyre.public_ip
}
output "drogon_ubuntu_ip" {
  value = aws_instance.drogon.public_ip
}
output "kali_ip" {
  value = aws_instance.kali1.public_ip
}
output "Windows_Admin_Password" {
  value = rsadecrypt(aws_instance.vhagar.password_data, file(var.oceanlotus-private-key-file))
}

