# Self Signed Certificate Authority

- [Self Signed Certificate Authority](#self-signed-certificate-authority)
  - [Summary](#summary)
  - [Example Certificate Authority Creation](#example-certificate-authority-creation)
    - [Create Host Certificate](#create-host-certificate)
  - [Install on Snake Windows Domain](#install-on-snake-windows-domain)
  - [Update on Kali box](#update-on-kali-box)
    - [Install custom certificate on Kali box](#install-custom-certificate-on-kali-box)
    - [Setup nato-int\[.\]com redirect](#setup-nato-intcom-redirect)
    - [Update Wordpress installation](#update-wordpress-installation)
    - [Send Carbon Scenario Email](#send-carbon-scenario-email)

## Summary

[CloudFlare's CFSSL project](https://github.com/cloudflare/cfssl) was used to generate a certificate authority, intermediate certificate, and host certificate for the scenario, to emulate a valid issued TLS certificate.

## Example Certificate Authority Creation

The following provides an example of how to generate the CA, intermediate CA, and host certificate using CFSSL. A full explanation of CFSSL can be found on the project [GitHub](https://github.com/cloudflare/cfssl) page.

1. Update `ca.json`, `intermediate-ca.json`, and `host1.json` as appropriate to reflect the new certificate authority, certificate authority intermediate certificate, and host certificate for web host.
2. The `cfssl.json` provided has the needed roles predefined, but may need to be modified based on your particular needs.
3. Run the following commands to generate the CA certificate, and intermediate issuing certificate:

```shell
cfssl gencert -initca ca.json|cfssljson -bare ca
cfssl gencert -initca intermediate-ca.json| cfssljson -bare intermediate_ca
cfssl sign -ca ca.pem -ca-key ca-key.pem -config cfssl.json -profile intermediate_ca intermediate_ca.csr | cfssljson -bare intermediate_ca
```

### Create Host Certificate

1. Run the following command:

  1. ```shell
     cfssl gencert -ca intermediate_ca.pem -ca-key intermediate_ca-key.pem -config cfssl.json -profile=server host1.json|cfssljson -bare host-1-server
     ```
2. Jobs done.

## Install on Snake Windows Domain

Use Group Policy to deploy trusted certificate on domain.

1. Connect to Snake Active Directory controller (`berlios`)
2. Follow [directions from Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/distribute-certificates-to-client-computers-by-using-group-policy) to trust certificate authority and intermediate certificate on domain.
3. Deploy updated group policy to `nk` domain.

## Update on Kali box

### Install custom certificate on Kali box

From Kali, run `kali-install-custom-certs.sh`

### Setup nato-int[.]com redirect

From Kali, run `kali-set-nato-int-redirect.sh`

### Update Wordpress installation

From Kali, run `kali-update-wp.sh`

### Send Carbon Scenario Email

From Kali, run `kali-send-email.sh`
