# Red Team Setup

- [Red Team Setup](#red-team-setup)
  - [Red LAN](#red-lan)
    - [Red LAN Systems to Configure](#red-lan-systems-to-configure)
    - [Attack Platform - Modin](#attack-platform---modin)
    - [Jumpbox - Stelio](#jumpbox---stelio)

## Red LAN

### Red LAN Systems to Configure

### Attack Platform - Modin

- Install
  - Run [files/support/kali/kali-prereqs.sh](files/support/kali/kali-prereqs.sh)
  - Follow instructions to setup [watering_hole](./files/watering_hole/README.md)
  - Run [files/support/kali/kali-install-custom-certs.sh](files/support/kali/kali-install-custom-certs.sh)
  - Run [files/support/kali/kali-update.sh](files/support/kali/kali-update.sh)
  - Run [files/support/kali/kali-update-wp.sh](files/support/kali/kali-update-wp.sh)
  - Run [files/support/kali/kali-set-nato-int-redirect.sh](files/support/kali/kali-set-nato-int-redirect.sh)
  - Run [files/support/kali/kali-send-email.sh](files/support/kali/kali-send-email.sh)
- Configuration
  - Install [files/support/kali/kali-postfix-conf](files/support/kali/kali-postfix-conf) to `/etc/postfix/main.cf`
  - Install [files/support/kali/kali-home-cradwell-procmailrc](files/support/kali/kali-home-cradwell-procmailrc) to `/home/cradwell/.procmailrc`
    - Set proper file ownership on `.procmailrc` file, and make mail directories, run:
      - `mkdir -p /home/cradwell/mail`
      - `chown -R cradwell:cradwell /home/cradwell/.procmailrc /home/cradwell/mail`
  - Enable and start postfix, run:
    - `systemctl enable --now postfix`
  - Ensure Apache and Mariadb are enabled
    - `systemctl enable --now mysql`
    - `systemctl enable --now apache2`

### Jumpbox - Stelio

The Windows Jumpbox requires minimal configuration.

- Configuration
  - Run [files/common/chocolatey-install.ps1](files/common/chocolatey-install.ps1)
  - Run [files/common/choco-install-packages.ps1](files/common/choco-install-packages.ps1)
  - Run [files/common/disable-firewall.ps1](files/common/disable-firewall.ps1)
  - Run [files/common/configure-jumpbox.ps1](files/common/configure-jumpbox.ps1)
