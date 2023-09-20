# Getting Started

This document covers the infrastructure setup for emulating Turla in Round 5 of ATT&CK Evaluations Enterprise.

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Terraform](#terraform)
  - [Detections vs Protections](#detections-vs-protections)
  - [Setup Guides](#setup-guides)
    - [Support - Setup First](#support---setup-first)
    - [Carbon](#carbon)
    - [Snake](#snake)
    - [Red Team](#red-team)

## Prerequisites

It is assumed you have a working knowledge of the following concepts and access to related tools:

* [Terraform](https://developer.hashicorp.com/terraform/downloads),

*  [PowerShell](https://learn.microsoft.com/en-us/powershell/),
*  Linux Shell Scripting (e.g. bash),
*  Existing Microsoft Azure with permissions to perform required actions (create manage resources including VM instances, VNETs, Virtual Network Gateways, and related resources),
*  [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli),
*  Concepts such as DNS, Email,
*  PKI,
*  and common system administration concepts for Windows and Linux

## Terraform

Terraform is used to initialize the Turla infrastructure.

<img src="assets/Turla-Infrastructure-Diagram.png" alt="Turla Diagram" style="zoom: 50%;" />

**NOTE**: You may be prompted to accept the Terms and subscribe for the Kali image in the Azure Marketplace. If prompted, follow the URL provided in the terminal and click the Subscribe button. Once the process completes, re-run the Terraform plan and apply commands below.

1. Create a Terraform settings file from the included template.
   1. `cp -a deploy.auto.tfvars.template deploy.auto.tfvars`
   2. Open the `deploy.auto.tfvars` in an editor, and configure with desired values.
2. Time to run Terraform.
   1. Initialize your Terraform environment.
      1. `terraform init`
   2. Validate your Terraform configuration.
      1. `terraform validate`
   3. Plan your deployment with Terraform.
      1. `terraform plan --out=tfplan`
   4. Execute the Terraform plan created in the previous step.
      1. `terraform apply tfplan`
      2. NOTE: This step may take a 15-30 minutes to properly provision all resources. This is normal.
   6. You are done, celebrate!

## Detections vs Protections

For the Turla evaluation, the Protections evaluation was conducted on a clone of the Detections range. Therefore there is only one infrastructure configuration, there is no differernce from an Infrastructure perspective whether the environment is used for Detections or Protections, all setup is identical.

## Setup Guides

There are four components of the Turla infrastructure, each broken out below. Each guide assumes the infrastructure has already been setup with Terraform.

### Support - Setup First

Contains resources that support the entire range, such as DNS, mail, and traffic redirection. Should be setup first, prior to configuring other components.

See [Setup Support](./Setup-Support.md) for details.

### Carbon

Contains resources related to the Carbon scenario, also referenced as "Scenario 1".

See [Setup Carbon](./Setup-Carbon.md)  for details.

### Snake

Contains resources related to the Snake scenario, also referenced as "Scenario 2".

See [Setup Snake](./Setup-Snake.md) for details.

### Red Team

Contains resources that support Red Team activity directly.

See [Setup Red Team](./Setup-RedTeam.md) for details.
