#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# kali-install-custom-certs.sh - install custom certs for attack platform

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/

# Usage: kali-install-custom-certs.sh

# ---------------------------------------------------------------------------

cert_file="/etc/ssl/certs/ssl-traffic.pem"
key_file="/etc/ssl/private/ssl-traffic.key"
tstamp=$(date +"%Y%m%d%H%M")

# Check if running as sudo
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# move originals out of the way if they exist
if [ -f ${cert_file} ]; then
  echo "moving cert file out of the way..."
  mv -f ${cert_file} ${cert_file}."${tstamp}"
fi

if [ -f ${key_file} ]; then
  echo "moving key file out of the way..."
  mv -f ${key_file} ${key_file}."${tstamp}"
fi

echo "writing cert file..."
# file contents sourced from: files/certificates/self-signed-ca/host-1-server.pem
cat <<'EOF' > ${cert_file}

-----BEGIN CERTIFICATE-----
MIIEVDCCAzygAwIBAgIUbw8nNs9941vNVWtLh0W+RVRHxowwDQYJKoZIhvcNAQEL
BQAwgZYxCzAJBgNVBAYTAkdCMRAwDgYDVQQIEwdFbmdsYW5kMRMwEQYDVQQHEwpN
YW5jaGVzdGVyMRQwEgYDVQQKEwtTdXBlciBDZXJ0czEkMCIGA1UECxMbU3VwZXIg
Q2VydHMgSW50ZXJtZWRpYXRlIENBMSQwIgYDVQQDExtTdXBlciBDZXJ0cyBJbnRl
cm1lZGlhdGUgQ0EwHhcNMjMwMjE1MjIxNDAwWhcNMjQwMjE1MjIxNDAwWjCBgjEL
MAkGA1UEBhMCVUExFDASBgNVBAgTC0t5aXYgT2JsYXN0MQ0wCwYDVQQHEwRLeWl2
MRgwFgYDVQQKEw9Tdm9ib2RhIFVrcmF5aW4xGDAWBgNVBAsTD1N2b2JvZGEgVWty
YXlpbjEaMBgGA1UEAxMRc3ZvYm9kYXVrcmF5aW4udWEwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDXZlo4NMGZ1ceXPg87krh/b3rO+5dwzb1paLHlTY9R
dMGT1LiyY4/iwlLQTnqRx9zq/s4c0u9wEUnsAKvWnWD4YODLDQ+Y16cFx0pdmCrT
ZS7nH9QmiZmlpKvXODFAHfG+4idtIH5iyHAd1qUoBk1Z48LJteoxb/eqcu7MSeId
nqBFFgGTjSfyt2HxfTvmCUaZJrQxWiWkTKTZr9oPXnGZWhkeExq5336txkIKoOjX
UkbI7V4isa3ayVgo2mDPNnOjMCZFrWiQF+tsen7gBTd2HrRDHKdqnprYRZHiNalX
v3dalL6KoLJSKpyQilaaQDEKtYHZ4uiY/8JGyc9UUoEhAgMBAAGjgaswgagwDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw
HQYDVR0OBBYEFOYKxK6drCivAlS/pvLIOn/WQCnhMB8GA1UdIwQYMBaAFKdDQMyJ
TFScxYpSFxl5jV5cZVL3MDMGA1UdEQQsMCqCEXN2b2JvZGF1a3JheWluLnVhghV3
d3cuc3ZvYm9kYXVrcmF5aW4udWEwDQYJKoZIhvcNAQELBQADggEBAJcHRvzwypWO
g3qSt5C002m38pIk7VcsWfQlT5YP4EQ9MX9FseB6MKAImqUc9PxZJrxp+b76rn61
0ByMopc+e3b6em8blUIVLymrDn1F+KGGGabeHcKiIWXf+6on3lR63iu1+14JgKP6
DOkyofMxSISJkS3gaP2sA1KcCY4BWupHZxoINfj4tS1/H1NBeTOmqmCGpZfu5Tpv
ITX/muuiz5mY5RWm+48ARK+uCDaICce4LK/6A9XS72SvbHswBS/I7A5B0LPYi8i0
1TyXMD9oXpqhSA4AjLn99rLEirPPwBzYiP90ggzA3AFywBoqdblLiMxPGLDCC3FP
V4rfigifHCg=
-----END CERTIFICATE-----

EOF

echo "writing key file..."
# file contents sourced from git: utils/self-signed-ca/host-1-server-key.pem
cat <<'EOF' > ${key_file}
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA12ZaODTBmdXHlz4PO5K4f296zvuXcM29aWix5U2PUXTBk9S4
smOP4sJS0E56kcfc6v7OHNLvcBFJ7ACr1p1g+GDgyw0PmNenBcdKXZgq02Uu5x/U
JomZpaSr1zgxQB3xvuInbSB+YshwHdalKAZNWePCybXqMW/3qnLuzEniHZ6gRRYB
k40n8rdh8X075glGmSa0MVolpEyk2a/aD15xmVoZHhMaud9+rcZCCqDo11JGyO1e
IrGt2slYKNpgzzZzozAmRa1okBfrbHp+4AU3dh60Qxynap6a2EWR4jWpV793WpS+
iqCyUiqckIpWmkAxCrWB2eLomP/CRsnPVFKBIQIDAQABAoIBAQC3l1qge37kEs16
wH+VRDoTDD69er2afRHLbVvrWM8mG4D+8pm2GpxCJ2UUfT+FT7ehaCrfcH56o5HB
INVWKG/FZDVVfD1mBbErgLCG07L02VI/1uYpLrER+SgqWY/I2Xz6OKJoJgDzS2oc
VJ4SXkTBsBqPeIkzN/79fdbBstuSZ9hf5xvW4TW4vZrktbgRcpACP5VoXna7exkX
H+sVNfVxm+306q+sYwPKXIWoLAL5GbhW5Bagt1LCyfhspPS7XcbInsa6Imtlmrwm
hOUGot3Z0vIaEG1K95hqfcGJfP0XHl4h/UNWFgSy13cN/9ZPd/g5NQDpY/+Dk4CM
YehcRDH9AoGBAOptXqWQj1acO/Y/2n6KuOL4zzgRNUjKLWnrDP156JZ6BDAjJ5US
pInSzqfegoujC2AYI7+tV0brLfl8HkhEJncRutM5UMPC94lpBnKPBFGstwE4Onsm
DCBo0/3b4iJUGXxfeuaGNPounOK22O+EVqWjRDGzNweygsRR5jd/E3CDAoGBAOs4
vEczUr8ckM51waTF3Eztgc0NRHBa6KPNntUQBcIVQrDsCBXDq0ZoU9DoeuhDwncQ
pJmXmhSK+INZc4lerJAg939X1DYA2pXcBERb7gb8t4fLAhwoLArnYQ+iqaOCujVd
wbY8D5tyEE3rWgW7mC4RCMjCXBzGMScJ8hhD6c6LAoGAFBEsquuG+ZkCIQAySebC
ENvPkTMX5pU38fsm74PB/y+OsDgyKTahUxLykbggYKeiT6WBWeUStYVoOBUB2pnK
2SJxZadgXIGSAvc0kBXh/sPUHoybpPMK0rNmgjKSVvHwBI9/y7/tRQU8dMPGKiqf
6CnjqoV2znffbcK8/D8qgNUCgYEAwLY54ueUiojfxpbJcLK+O7R2nMWa5aZFZTZo
Q80dupXqjsLCGPq3TzbYPJbLY5FoOF5FTKTdEqmM0ygtNUWAgZDQ1N7jON9YNmEM
iej7SXQw9SsIboMnGkPYzJOLAjBvWJuYwjHQ45z+6KfCmGHKWyuPk9NQ3i4uRPqs
At9ZJeMCgYEAgMPSny++vmap2RlDJIqqXWsbnl3kAgxHN6Vl1lHlmx2UqWNjLWaa
U0b+S0dOmmB/C85YOLRT/cHvjOQVccphhN3tXG60oae6ISI9HydE8wf/CwXyy5QW
9IF04KQU1MDbm3QcQdE6jE/bwoj74PKGv6IRhf4Lat4/p5kxNoUiLdg=
-----END RSA PRIVATE KEY-----

EOF

# fixing ownership and permissions
chown root:ssl-cert ${key_file}
chown root:root ${cert_file}
chmod 640 ${key_file}
chmod 644 ${cert_file}
