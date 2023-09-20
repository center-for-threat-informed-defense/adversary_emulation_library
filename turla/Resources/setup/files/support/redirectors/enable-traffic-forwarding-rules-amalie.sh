#!/usr/bin/env bash

# ---------------------------------------------------------------------------
# enable-traffic-forwarding-rules-amalie.sh - Enable traffic forwarding rules

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in 
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License 
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express 
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: enable-traffic-forwarding-rules-amalie.sh

# --------------------------------------------------------------------------- 

# amalie traffic forwarding

############ rules ##############
iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 80 -j DNAT --to-destination 176.59.15.33:8080
iptables -t nat -A PREROUTING -p tcp -i eth1 --dport 80 -j DNAT --to-destination 176.59.15.33:8082
iptables -t nat -A PREROUTING -p tcp -i eth2 --dport 80 -j DNAT --to-destination 176.59.15.33:8082
iptables -t nat -A POSTROUTING -j MASQUERADE

# print out updated nat
iptables -L -t nat -v
