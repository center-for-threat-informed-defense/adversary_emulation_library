# R5 Infrastructure Project

## Evals Round 5


<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >=1.1.0 |
| <a name="requirement_azurerm"></a> [azurerm](#requirement\_azurerm) | <=3.43 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | 3.43.0 |
| <a name="provider_random"></a> [random](#provider\_random) | 3.5.1 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_boltnet-redirect-srv1"></a> [boltnet-redirect-srv1](#module\_boltnet-redirect-srv1) | ../modules/linuxsrv-latest-static | n/a |
| <a name="module_boltnet-redirect-srv2"></a> [boltnet-redirect-srv2](#module\_boltnet-redirect-srv2) | ../modules/linuxsrv-latest-static | n/a |
| <a name="module_boltnet-redirect-srv3"></a> [boltnet-redirect-srv3](#module\_boltnet-redirect-srv3) | ../modules/linuxsrv-latest-static | n/a |
| <a name="module_carbon-ad-srv1"></a> [carbon-ad-srv1](#module\_carbon-ad-srv1) | ../modules/winsrv-latest-static | n/a |
| <a name="module_carbon-desk1"></a> [carbon-desk1](#module\_carbon-desk1) | ../modules/windesk-latest-static | n/a |
| <a name="module_carbon-desk2"></a> [carbon-desk2](#module\_carbon-desk2) | ../modules/windesk-latest-static | n/a |
| <a name="module_carbon-desk3"></a> [carbon-desk3](#module\_carbon-desk3) | ../modules/windesk-latest-static | n/a |
| <a name="module_carbon-ex-srv1"></a> [carbon-ex-srv1](#module\_carbon-ex-srv1) | ../modules/winsrv-latest-static | n/a |
| <a name="module_carbon-web-srv1"></a> [carbon-web-srv1](#module\_carbon-web-srv1) | ../modules/linuxsrv-latest-static | n/a |
| <a name="module_red-kali1"></a> [red-kali1](#module\_red-kali1) | ../modules/linuxsrv-latest-static | n/a |
| <a name="module_rgroup"></a> [rgroup](#module\_rgroup) | ../modules/rgroup | n/a |
| <a name="module_snake-ad-srv1"></a> [snake-ad-srv1](#module\_snake-ad-srv1) | ../modules/winsrv-latest-static | n/a |
| <a name="module_snake-desk1"></a> [snake-desk1](#module\_snake-desk1) | ../modules/windesk-latest-static | n/a |
| <a name="module_snake-desk2"></a> [snake-desk2](#module\_snake-desk2) | ../modules/windesk-latest-static | n/a |
| <a name="module_snake-ex-srv1"></a> [snake-ex-srv1](#module\_snake-ex-srv1) | ../modules/winsrv-latest-static | n/a |
| <a name="module_snake-file-srv1"></a> [snake-file-srv1](#module\_snake-file-srv1) | ../modules/winsrv-latest-static | n/a |
| <a name="module_support-dns-srv1"></a> [support-dns-srv1](#module\_support-dns-srv1) | ../modules/linuxsrv-latest-static | n/a |
| <a name="module_support-jumpbox-srv1"></a> [support-jumpbox-srv1](#module\_support-jumpbox-srv1) | ../modules/winsrv-latest-static | n/a |
| <a name="module_support-pf-srv1"></a> [support-pf-srv1](#module\_support-pf-srv1) | ../modules/linuxsrv-latest-static | n/a |
| <a name="module_support-web-srv3"></a> [support-web-srv3](#module\_support-web-srv3) | ../modules/linuxsrv-latest-static | n/a |

## Resources

| Name | Type |
|------|------|
| [azurerm_public_ip.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/public_ip) | resource |
| [azurerm_subnet.boltnet](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_subnet.carbon_desk](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_subnet.carbon_srv](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_subnet.red](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_subnet.snake_desk_v2](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_subnet.snake_srv_v2](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_subnet.support](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_subnet.vpn](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet) | resource |
| [azurerm_virtual_network.vnet1](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network) | resource |
| [azurerm_virtual_network.vnet2](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network) | resource |
| [azurerm_virtual_network.vnet3](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network) | resource |
| [azurerm_virtual_network_gateway.main](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_gateway) | resource |
| [azurerm_virtual_network_peering.peer1to2](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_peering) | resource |
| [azurerm_virtual_network_peering.peer1to3](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_peering) | resource |
| [azurerm_virtual_network_peering.peer2to1](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_peering) | resource |
| [azurerm_virtual_network_peering.peer2to3](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_peering) | resource |
| [azurerm_virtual_network_peering.peer3to1](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_peering) | resource |
| [azurerm_virtual_network_peering.peer3to2](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_network_peering) | resource |
| [random_id.id-random](https://registry.terraform.io/providers/hashicorp/random/latest/docs/resources/id) | resource |
| [azurerm_client_config.current](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/client_config) | data source |
| [azurerm_subscription.current](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/subscription) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_carbon_desk_1_hostname"></a> [carbon\_desk\_1\_hostname](#input\_carbon\_desk\_1\_hostname) | n/a | `string` | `"hobgoblin"` | no |
| <a name="input_carbon_desk_1_ip"></a> [carbon\_desk\_1\_ip](#input\_carbon\_desk\_1\_ip) | n/a | `string` | `"10.20.20.102"` | no |
| <a name="input_carbon_desk_2_hostname"></a> [carbon\_desk\_2\_hostname](#input\_carbon\_desk\_2\_hostname) | n/a | `string` | `"domovoy"` | no |
| <a name="input_carbon_desk_2_ip"></a> [carbon\_desk\_2\_ip](#input\_carbon\_desk\_2\_ip) | n/a | `string` | `"10.20.20.103"` | no |
| <a name="input_carbon_desk_3_hostname"></a> [carbon\_desk\_3\_hostname](#input\_carbon\_desk\_3\_hostname) | n/a | `string` | `"khabibulin"` | no |
| <a name="input_carbon_desk_3_ip"></a> [carbon\_desk\_3\_ip](#input\_carbon\_desk\_3\_ip) | n/a | `string` | `"10.20.20.104"` | no |
| <a name="input_carbon_srv_ad_hostname"></a> [carbon\_srv\_ad\_hostname](#input\_carbon\_srv\_ad\_hostname) | n/a | `string` | `"bannik"` | no |
| <a name="input_carbon_srv_ad_ip"></a> [carbon\_srv\_ad\_ip](#input\_carbon\_srv\_ad\_ip) | n/a | `string` | `"10.20.10.9"` | no |
| <a name="input_carbon_srv_ex_hostname"></a> [carbon\_srv\_ex\_hostname](#input\_carbon\_srv\_ex\_hostname) | n/a | `string` | `"brieftragerin"` | no |
| <a name="input_carbon_srv_ex_ip"></a> [carbon\_srv\_ex\_ip](#input\_carbon\_srv\_ex\_ip) | n/a | `string` | `"10.20.10.17"` | no |
| <a name="input_carbon_srv_web_hostname"></a> [carbon\_srv\_web\_hostname](#input\_carbon\_srv\_web\_hostname) | n/a | `string` | `"kagarov"` | no |
| <a name="input_carbon_srv_web_ip"></a> [carbon\_srv\_web\_ip](#input\_carbon\_srv\_web\_ip) | n/a | `string` | `"10.20.10.23"` | no |
| <a name="input_carbon_support_c2_ip_list"></a> [carbon\_support\_c2\_ip\_list](#input\_carbon\_support\_c2\_ip\_list) | IPs to be assigned to C2 | `list(string)` | <pre>[<br>  "91.52.62.64",<br>  "91.52.62.137",<br>  "91.52.62.203"<br>]</pre> | no |
| <a name="input_carbon_win_ad_srv_os_azure_source_image_sku"></a> [carbon\_win\_ad\_srv\_os\_azure\_source\_image\_sku](#input\_carbon\_win\_ad\_srv\_os\_azure\_source\_image\_sku) | Sku for Windows Server to use (Carbon AD server only) | `string` | `"2019-datacenter"` | no |
| <a name="input_carbon_win_ad_srv_os_azure_source_image_version"></a> [carbon\_win\_ad\_srv\_os\_azure\_source\_image\_version](#input\_carbon\_win\_ad\_srv\_os\_azure\_source\_image\_version) | Version for Windows Server to use (Carbon AD server only) | `string` | `"17763.3406.220909"` | no |
| <a name="input_carbon_win_desk_os_azure_source_image_sku"></a> [carbon\_win\_desk\_os\_azure\_source\_image\_sku](#input\_carbon\_win\_desk\_os\_azure\_source\_image\_sku) | Sku for Windows Server to use (Carbon) | `string` | `"win10-21h2-pro-g2"` | no |
| <a name="input_carbon_win_desk_os_azure_source_image_version"></a> [carbon\_win\_desk\_os\_azure\_source\_image\_version](#input\_carbon\_win\_desk\_os\_azure\_source\_image\_version) | Version for Windows Server to use (Carbon) | `string` | `"19044.2006.220909"` | no |
| <a name="input_carbon_win_srv_os_azure_source_image_sku"></a> [carbon\_win\_srv\_os\_azure\_source\_image\_sku](#input\_carbon\_win\_srv\_os\_azure\_source\_image\_sku) | Sku for Windows Server to use (Carbon) | `string` | `"2019-datacenter"` | no |
| <a name="input_carbon_win_srv_os_azure_source_image_version"></a> [carbon\_win\_srv\_os\_azure\_source\_image\_version](#input\_carbon\_win\_srv\_os\_azure\_source\_image\_version) | Version for Windows Server to use (Carbon) | `string` | `"2019.0.20190410"` | no |
| <a name="input_detlab_srv_hostname"></a> [detlab\_srv\_hostname](#input\_detlab\_srv\_hostname) | Detlab hostname | `string` | `"kontos"` | no |
| <a name="input_detlab_srv_ip"></a> [detlab\_srv\_ip](#input\_detlab\_srv\_ip) | n/a | `string` | `"176.59.15.55"` | no |
| <a name="input_dev_linux_password"></a> [dev\_linux\_password](#input\_dev\_linux\_password) | Password for dev Linux hosts | `string` | n/a | yes |
| <a name="input_dev_linux_username"></a> [dev\_linux\_username](#input\_dev\_linux\_username) | Username for Linux hosts | `string` | n/a | yes |
| <a name="input_dev_win_admin_password"></a> [dev\_win\_admin\_password](#input\_dev\_win\_admin\_password) | Password for Windows 10 desktop dev boxes | `string` | n/a | yes |
| <a name="input_dev_win_admin_username"></a> [dev\_win\_admin\_username](#input\_dev\_win\_admin\_username) | Username for Windows 10 desktop dev boxes | `string` | `"devadmin"` | no |
| <a name="input_location"></a> [location](#input\_location) | Azure location/region for resources | `string` | n/a | yes |
| <a name="input_name-prefix"></a> [name-prefix](#input\_name-prefix) | String prefix for resource names | `string` | n/a | yes |
| <a name="input_red_jumpbox_hostname"></a> [red\_jumpbox\_hostname](#input\_red\_jumpbox\_hostname) | n/a | `string` | `"stelio"` | no |
| <a name="input_red_jumpbox_ip"></a> [red\_jumpbox\_ip](#input\_red\_jumpbox\_ip) | n/a | `string` | `"176.59.15.13"` | no |
| <a name="input_red_kali_platform_hostname"></a> [red\_kali\_platform\_hostname](#input\_red\_kali\_platform\_hostname) | n/a | `string` | `"modin"` | no |
| <a name="input_red_kali_platform_ip_list"></a> [red\_kali\_platform\_ip\_list](#input\_red\_kali\_platform\_ip\_list) | n/a | `list(string)` | <pre>[<br>  "176.59.15.33",<br>  "176.59.15.44"<br>]</pre> | no |
| <a name="input_red_postfix_hostname"></a> [red\_postfix\_hostname](#input\_red\_postfix\_hostname) | n/a | `string` | `"richards"` | no |
| <a name="input_red_web_hostname"></a> [red\_web\_hostname](#input\_red\_web\_hostname) | n/a | `string` | `"clymer"` | no |
| <a name="input_snake_desk_1_hostname"></a> [snake\_desk\_1\_hostname](#input\_snake\_desk\_1\_hostname) | n/a | `string` | `"uosis"` | no |
| <a name="input_snake_desk_1_ip"></a> [snake\_desk\_1\_ip](#input\_snake\_desk\_1\_ip) | n/a | `string` | `"10.100.40.102"` | no |
| <a name="input_snake_desk_2_hostname"></a> [snake\_desk\_2\_hostname](#input\_snake\_desk\_2\_hostname) | n/a | `string` | `"azuolas"` | no |
| <a name="input_snake_desk_2_ip"></a> [snake\_desk\_2\_ip](#input\_snake\_desk\_2\_ip) | n/a | `string` | `"10.100.40.103"` | no |
| <a name="input_snake_srv_ad_hostname"></a> [snake\_srv\_ad\_hostname](#input\_snake\_srv\_ad\_hostname) | n/a | `string` | `"berlios"` | no |
| <a name="input_snake_srv_ad_ip"></a> [snake\_srv\_ad\_ip](#input\_snake\_srv\_ad\_ip) | n/a | `string` | `"10.100.30.202"` | no |
| <a name="input_snake_srv_ex_hostname"></a> [snake\_srv\_ex\_hostname](#input\_snake\_srv\_ex\_hostname) | n/a | `string` | `"drebule"` | no |
| <a name="input_snake_srv_ex_ip"></a> [snake\_srv\_ex\_ip](#input\_snake\_srv\_ex\_ip) | n/a | `string` | `"10.100.30.203"` | no |
| <a name="input_snake_srv_file_hostname"></a> [snake\_srv\_file\_hostname](#input\_snake\_srv\_file\_hostname) | n/a | `string` | `"berzas"` | no |
| <a name="input_snake_srv_file_ip"></a> [snake\_srv\_file\_ip](#input\_snake\_srv\_file\_ip) | n/a | `string` | `"10.100.30.204"` | no |
| <a name="input_snake_support_c2_ip_list"></a> [snake\_support\_c2\_ip\_list](#input\_snake\_support\_c2\_ip\_list) | IPs to be assigned to C2 | `list(string)` | <pre>[<br>  "91.52.201.31",<br>  "91.52.201.98",<br>  "91.52.201.119"<br>]</pre> | no |
| <a name="input_snake_support_c2_ip_list_2"></a> [snake\_support\_c2\_ip\_list\_2](#input\_snake\_support\_c2\_ip\_list\_2) | IPs to be assigned to C2 | `list(string)` | <pre>[<br>  "91.52.201.144",<br>  "91.52.201.202"<br>]</pre> | no |
| <a name="input_snake_win_desk_os_azure_source_image_sku"></a> [snake\_win\_desk\_os\_azure\_source\_image\_sku](#input\_snake\_win\_desk\_os\_azure\_source\_image\_sku) | Sku for Windows Server to use (snake) | `string` | `"19h1-pro-gensecond"` | no |
| <a name="input_snake_win_desk_os_azure_source_image_version"></a> [snake\_win\_desk\_os\_azure\_source\_image\_version](#input\_snake\_win\_desk\_os\_azure\_source\_image\_version) | Version for Windows Server to use (snake) | `string` | `"18362.1256.2012032308"` | no |
| <a name="input_snake_win_srv_os_azure_source_image_sku"></a> [snake\_win\_srv\_os\_azure\_source\_image\_sku](#input\_snake\_win\_srv\_os\_azure\_source\_image\_sku) | Sku for Windows Server to use (snake) | `string` | `"2019-datacenter"` | no |
| <a name="input_snake_win_srv_os_azure_source_image_version"></a> [snake\_win\_srv\_os\_azure\_source\_image\_version](#input\_snake\_win\_srv\_os\_azure\_source\_image\_version) | Version for Windows Server to use (snake) | `string` | `"17763.3406.220909"` | no |
| <a name="input_ssh_private_key_path"></a> [ssh\_private\_key\_path](#input\_ssh\_private\_key\_path) | Path to SSH private key to use for Linux ssh systems (public and private key must be matching pair) | `string` | n/a | yes |
| <a name="input_ssh_public_key_path"></a> [ssh\_public\_key\_path](#input\_ssh\_public\_key\_path) | Path to SSH public key to use for Linux ssh systems (public and private key must be matching pair) | `string` | n/a | yes |
| <a name="input_support_dns_hostname"></a> [support\_dns\_hostname](#input\_support\_dns\_hostname) | n/a | `string` | `"stlouis"` | no |
| <a name="input_support_dns_ip"></a> [support\_dns\_ip](#input\_support\_dns\_ip) | n/a | `string` | `"91.52.201.22"` | no |
| <a name="input_support_postfix_ip"></a> [support\_postfix\_ip](#input\_support\_postfix\_ip) | n/a | `string` | `"91.52.201.29"` | no |
| <a name="input_support_web_ip"></a> [support\_web\_ip](#input\_support\_web\_ip) | n/a | `string` | `"91.52.201.21"` | no |
| <a name="input_vnet1-address-space"></a> [vnet1-address-space](#input\_vnet1-address-space) | vnet 1 address space | `string` | `"10.20.0.0/16"` | no |
| <a name="input_vnet1-address-space-2"></a> [vnet1-address-space-2](#input\_vnet1-address-space-2) | Additional address range for vnet1 | `string` | `"10.100.0.0/16"` | no |
| <a name="input_vnet1-sub1-range"></a> [vnet1-sub1-range](#input\_vnet1-sub1-range) | IP range of subnet 1 on vnet 1 (must be within vnet 1 address space) | `string` | `"10.20.10.0/24"` | no |
| <a name="input_vnet1-sub2-range"></a> [vnet1-sub2-range](#input\_vnet1-sub2-range) | IP range of subnet 2 on vnet 1 (must be within vnet 1 address space) | `string` | `"10.20.20.0/24"` | no |
| <a name="input_vnet1-sub3-range"></a> [vnet1-sub3-range](#input\_vnet1-sub3-range) | IP range of subnet 3 on vnet 1 (must be within vnet 1 address space) | `string` | `"10.100.30.0/24"` | no |
| <a name="input_vnet1-sub4-range"></a> [vnet1-sub4-range](#input\_vnet1-sub4-range) | IP range of subnet 4 on vnet 1 (must be within vnet 1 address space) | `string` | `"10.100.40.0/24"` | no |
| <a name="input_vnet1-sub5-range"></a> [vnet1-sub5-range](#input\_vnet1-sub5-range) | IP range of subnet 5 on vnet 1 (must be within vnet 1 address space) | `string` | `"10.20.50.0/24"` | no |
| <a name="input_vnet1-sub6-range"></a> [vnet1-sub6-range](#input\_vnet1-sub6-range) | IP range of subnet 5 on vnet 1 (must be within vnet 1 address space) | `string` | `"10.20.60.0/24"` | no |
| <a name="input_vnet2-address-space"></a> [vnet2-address-space](#input\_vnet2-address-space) | vnet 2 address space | `string` | `"176.59.0.0/16"` | no |
| <a name="input_vnet2-sub1-range"></a> [vnet2-sub1-range](#input\_vnet2-sub1-range) | IP range of subnet (must be within vnet 2 address space) | `string` | `"176.59.15.0/24"` | no |
| <a name="input_vnet3-address-space"></a> [vnet3-address-space](#input\_vnet3-address-space) | vnet 3 address space | `string` | `"91.52.0.0/16"` | no |
| <a name="input_vnet3-sub1-range"></a> [vnet3-sub1-range](#input\_vnet3-sub1-range) | IP range of subnet on vnet 3 (must be within vnet 3 address space) | `string` | `"91.52.62.0/24"` | no |
| <a name="input_vnet3-sub2-range"></a> [vnet3-sub2-range](#input\_vnet3-sub2-range) | IP range of subnet on vnet 3 (must be within vnet 3 address space) | `string` | `"91.52.201.0/24"` | no |
| <a name="input_win_carbon_domain_name"></a> [win\_carbon\_domain\_name](#input\_win\_carbon\_domain\_name) | Domain name for Carbon | `string` | `"skt.local"` | no |
| <a name="input_win_carbon_netbios_name"></a> [win\_carbon\_netbios\_name](#input\_win\_carbon\_netbios\_name) | Netbios name for Carbon | `string` | `"skt"` | no |
| <a name="input_win_domain_name"></a> [win\_domain\_name](#input\_win\_domain\_name) | Domain name for AD | `string` | n/a | yes |
| <a name="input_win_netbios_name"></a> [win\_netbios\_name](#input\_win\_netbios\_name) | Netbios name for AD | `string` | n/a | yes |
| <a name="input_win_snake_domain_name"></a> [win\_snake\_domain\_name](#input\_win\_snake\_domain\_name) | Domain name for Snake | `string` | `"nk.local"` | no |
| <a name="input_win_snake_netbios_name"></a> [win\_snake\_netbios\_name](#input\_win\_snake\_netbios\_name) | Netbios name for Snake | `string` | `"nk"` | no |
| <a name="input_win_srv_admin_password"></a> [win\_srv\_admin\_password](#input\_win\_srv\_admin\_password) | Windows server admin password | `string` | n/a | yes |
| <a name="input_win_srv_admin_username"></a> [win\_srv\_admin\_username](#input\_win\_srv\_admin\_username) | Windows Server admin username | `string` | n/a | yes |

## Outputs

No outputs.
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
