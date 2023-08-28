# OceanLotus Infrastructure Overview

[TOC]



## Setup

### Prerequisites

* Running on a system with the following tools pre-installed:

  * Existing AWS Account with permissions to perform required actions (create/manage resources including EC2 instances, VPCs, Internet Gateways, Security Groups, and related resources)

  * Tools

    * `ssh-keygen`, 
    * `bash` shell,
    * [Terraform](https://developer.hashicorp.com/terraform/downloads),
    * [Ansible](https://docs.ansible.com/)
    * [AWS CLI](https://aws.amazon.com/cli/) installed

  * Install

    * On Mac with [Homebrew](https://brew.sh/) installed

      * Example: 

      * ```
        brew tap hashicorp/tap
        brew install hashicorp/tap/terraform
        brew install ansible
        ```

    * On Linux, see [Terraform](https://developer.hashicorp.com/terraform/downloads) and [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/installation_distros.html) documentation


### Create SSH Key Pair

Run the `run_first.sh` script in this directory first. The script will generate a separate SSH key pair, that will be used for OceanLotus infrastructure.

`./run_first.sh`

After the script completes, you will have a new SSH private and public key pair, named `oceanlotus` and `oceanlotus.pub`, respectively.

### Get your Public IP

You will need to know your public IP address for the next steps. You can get it by searching Google for "what is my ip", or running `curl ifconfig.me` from the command line on a system with curl installed. For the rest of this document, your public IP will be referred to as `PUBLIC_IP`, replace the variable `PUBLIC_IP` with your actual public IP address.



| Public IP | `PUBLIC_IP` |
| --------- | ----------- |
|           |             |

## Terraform

Terraform is used to initialize the AWS infrastructure. 

<img src="assets/oceanlotus-Page-3.drawio.png" alt="oceanlotus-Page-3.drawio" style="zoom: 50%;" />

1. Create a Terraform settings file from the included template. 
   1. `cp -a oceanlotus.auto.tfvars.example oceanlotus.auto.tfvars`
   2. Open the `oceanlotus.auto.tfvars` in an editor
   3. Set the values for all the variables listed, and uncomment each line by removing the `#` at the beginning of the line.
      1. For AWS Profile, set to the profile name used by your AWS CLI.
      2. For the unique prefix, generate a random string sequence.
         1. The unique prefix should consist of lowercase letters and numbers only.
      3. For the IP whitelist, list each public IP address (identified in the earlier setup section) that will be accessing the OceanLotus resources.
2. Time to run Terraform.
   1. Initialize your Terraform environment.
      1. `terraform init`
   2. Validate your Terraform configuration.
      1. `terraform validate`
   3. Plan your deployment with Terraform.
      1. `terraform plan --out=tfplan`
   4. Execute the Terraform plan created in the previous step.
      1. `terraform apply tfplan`
      2. NOTE: This step may take a few minutes to properly provision all AWS resources. This is normal.
   5. View the Terraform output to get a list of public IP addresses for each resource, as well as the default password for the Windows server.
      1. `terraform output` (if you get a "No outputs found" message, run `terraform refresh`) 
   6. You are done, celebrate!

## Ansible

The Windows and Ubuntu hosts are configured with Ansible. The AWS Mac instance must be configured manually. The steps for configuring the AWS Mac instance are listed in the next section. 

#### Install Ansible dependencies

First, install the Ansible playbook requirements by running the following command: 

`ansible-galaxy install -r requirements.yml`

#### Retrieve the Windows Password

AWS generates a random password on creation of a Windows instance. 

1. To retrieve the password, view the output of `terraform output` from the previous step. 
2. Open the `ansible/inventory` text file in an editor
3. From the output from Terraform, paste the value for Windows_Admin_Password into the `ansible_password` section for the `vhagar` host. Replace the text `REPLACE_ME_WITH_Windows_Admin_Password` with your actual password output by Terraform earlier.

#### Update the Ansible Inventory

Update the IP addresses listed in the `inventory` file with the IPs output by `terraform output`. 

For `vhagar`, `dreamfyre`, and `drogon`, update the value of `ansible_host` with the IP address output by `terraform output`. 

#### Deploy Ansible Configuration

1. First, generate the Windows AD domain.
   1. `ansible-playbook -i inventory playbooks/windows.yml`
   2. Once the playbook completes successfully, move to next step.
2. Provision the Linux host.
   1. `ansible-playbook -i inventory playbooks/linux.yml`
   2. Once the playbook completes successfully, manually provision the Mac host.

## Post Configuration

#### Mac Host

Replace `MAC-IP` with the public IP of your Mac instance below.

1. SSH to Mac Host

   1. From your local machine: `ssh -i ./oceanlotus ec2-user@MAC-IP`

2. Set password for default ec2-user

   1. From the AWS Mac Instance: `sudo passwd ec2-user`

3. Enable VNC

   1. From the AWS Mac Instance: `sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \ -activate -configure -access -on \ -restart -agent -privs -all`

4. Create SSH Tunnel

   1. From your local machine: `ssh -L  5900:localhost:5900 -i ./oceanlotus ec2-user@MAC-IP`

5. Join to Domain

   1. From the AWS Mac instance: 

      1. Set DNS to Active Directory (vhagar) server: https://support.apple.com/lt-lt/guide/mac-help/mh14127/10.15/mac/10.15
      2. Set DNS server to `10.90.30.20`

   2. From the AWS Mac instance (replace PASSWORD with password for user):

      1. ```shell
         dsconfigad -force -add "viserion.com" -computer 10.90.30.20\
          -username hpotter -password 'noax3teenohb~e'\
          -localhome enable -useuncpath enable\
          -groups 'Domain Admins' -shell /bin/bash
         ```

6. You will now be able to connect to the Mac host.



## Important

VNC Connection to Mac

**NOTE**: Anytime you connect to the AWS Mac instance over VNC will require you to setup an SSH tunnel first. 

`ssh -L  5900:localhost:5900 -i ./oceanlotus ec2-user@MAC-IP`