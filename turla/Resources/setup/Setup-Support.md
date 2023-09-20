# Support LAN

- [Support LAN](#support-lan)
  - [Support LAN Systems to Configure](#support-lan-systems-to-configure)
    - [Redirectors](#redirectors)
    - [DNS](#dns)
    - [Mail](#mail)
    - [Web Server](#web-server)
    - [Traffic Redirectors](#traffic-redirectors)

## Support LAN Systems to Configure

### Redirectors

- Amalie - Redirector
  - enable-traffic-forwarding-rules-amalie.sh - Set up the traffic forwarding rules for amalie redirector
- Thunderbug - Redirector
  - enable-traffic-forwarding-rules-thunderbug.sh - Set up the traffic forwarding rules for thunderbug redirector
- Bolt - Redirector
  - enable-traffic-forwarding-rules-bolt.sh - Set up the traffic forwarding rules for bolt redirector


### DNS

`stlouis` DNS server supports DNS for the range.

- Install
  - `install-unbound-dns.sh` - Installs the Unbound DNS package on stlouis DNS server.
- Configuration
  - Install all files/support/dns/*.conf files to the `/etc/unbound/unbound.conf.d/` directory.

### Mail

The `stamp` server runs Postfix for the range. See [Email Flow](EmailFlow.md) for more details on how mail is routed.

- Install
  - As root, run the following commands to install Postfix and configure DNS:
    - `DEBIAN_FRONTEND=noninteractive apt install -y postfix ripmime mailutils procmail`
    - Run [files/support/mail/stamp-configure-dns.sh](./files/support/mail/stamp-configure-dns.sh) to configure DNS.
- Configuration
  - Install [files/support/mail/etc_mailname](./files/support/mail/etc_mailname) to `/etc/mailname`
  - Install [files/support/mail/etc_postfix_main.cf](./files/support/mail/etc_postfix_main.cf) to `/etc/postfix/main.cf`
  - Install [files/support/mail/etc_postfix_virtual.cf](./files/support/mail/etc_postfix_virtual.cf) to `/etc/postfix/virtual.cf`
  - Run `postmap /etc/postfix/virtual` to build the virtual domain aliases.
  - Run `systemctl enable --now postfix && systemctl restart postfix` to apply the new configuration.

### Web Server

- nato-int.com - Web Server

- Install
  - As root, run the following commands:
    - `apt update && apt install -y git etckeeper apache2 wget`
    - `hostnamectl  set-hostname nato-int.com`
    - `systemctl enable --now apache2`

### Traffic Redirectors

- Install
  - All Redirectors as root
    - `apt update && apt install -y netfilter-persistent`
    - Copy the following files to every redirector (destination doesn't matter, `/opt/` used for examples)
      - [files/support/redirectors/disable-traffic-forwarding-rules.sh](files/support/redirectors/disable-traffic-forwarding-rules.sh)
      - [files/support/redirectors/print-traffic-forwarding-rules.sh](files/support/redirectors/print-traffic-forwarding-rules.sh)
    - Copy the matching `enable-traffic-forwarding-HOSTNAME.sh` script to each redirector (e.g. `enable-traffic-forwarding-amalie.sh` to `amalie`)
    - Make scripts executable
      - `chmod +x /opt/*.sh`
  - Configuration
    - Run `/opt/enable-traffic-forwarding-HOSTNAME.sh` on each host
  - Control
    - View configuration
      - Run `/opt/print-traffic-forwarding-rules.sh` view the current forwarding configuration
    - Disable forwarding
      - Run `/opt/disable-traffic-forwarding-rules.sh` to disable forwarding.
