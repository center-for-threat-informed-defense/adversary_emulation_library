# Traffic Redirectors

Evaluations occurred in Microsoft Azure, which limits the number of network interfaces that can be attached to VM. Three redirectors were required to support traffic redirection for eight IP addresses.

Traffic redirection is performed using [iptables](https://www.netfilter.org/) NAT masquerading, with traffic sent to specific destination ports on a particular network interface being redirected to a specific IP address and port. Scripts in the setup/ folder provide the following functionality:

1. `enable-traffic-forwarding-rules-HOSTNAME.sh`
   1. Running the script on a server will configures network forwarding rules. Note that forwarding rules are based on network interfaces. As multiple IP addresses are attached to redirector VMs, double check the network interfaces are assigned to the expected IP addresses.
2. `disable-traffic-forwarding-rules.sh`
   1. Running the script on a server will disable and clear any network forwarding rules in place.
3. `print-traffic-forwarding-rules.sh`
   1. Running the script will print to stdout any network forwarding rules currently configured.

## Table of URLs and IPs used by Redirectors

| URL                         | IP               | Redirector Host  |
| --------------------------- | ---------------- | ---------------- |
| shoppingbeach[.]org         | `91.52.62.64`    | amalie, eth0     |
| prendre-des-vacances[.]fr   | `91.52.62.137`   | amalie, eth1     |
| eunewswire[.]eu             | `91.52.62.203`   | amalie, eth2     |
| svobodaukrayin[.]ua         | `91.52.201.31`   | thunderbug, eth0 |
| bestcafeswimxp2[.]com       | `91.52.201.98`   | thunderbug, eth1 |
| cheapinfomedical99[.]net    | `91.52.201.119`  | thunderbug, eth2 |
| gamesiteworldwide2023[.]org | `91.52.201.144`  | bolt, eth0       |
| anto-int[.]com              | `91.52.201.202`  | bolt, eth1       |
