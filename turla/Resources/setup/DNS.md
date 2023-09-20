# DNS Configuration

[Unbound DNS, by NLnet Labs](https://github.com/NLnetLabs/unbound), was used to provide DNS services for the range. The configuration is available in the `resources/dns` folder.

1. Run the `install-unbound-dns.sh` script on `stlouis`.
2. Copy the `resources/dns/*.conf` files to `stlouis` host to `/etc/unbound/unbound.conf.d/`
3. Restart the `unbound` service, `sudo systemctl restart unbound`.
