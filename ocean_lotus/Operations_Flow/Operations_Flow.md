# OceanLotus Operations Flow

| Step | CTI Operations Flow | Cited Intelligence |
| ------- | ----------- | ----------- | 
|1| Once the target has downloaded the second-stage payload, the attacker establishes persistence in the target’s machine. 2 documented backdoor implants downloaded are OSX.OceanLotus.D (variant D) and OSX.OceanLotus.F (variant F). Both backdoors plant persistence files in /Library/LaunchDaemons/ or ~/Library/LaunchAgents/ depending on their privileges ([T1543.001](https://attack.mitre.org/techniques/T1543/001/), [T1543.004](https://attack.mitre.org/techniques/T1543/004/)). These files masquerade as regular .plist files ([T1036.008](https://attack.mitre.org/techniques/T1036/008/)). </p> The implants encrypt their collected data prior to exfiltration ([T1573](https://attack.mitre.org/techniques/T1573/)) and use a series of defense evasion techniques to avoid detection in the victim’s system ([T1222.002](https://attack.mitre.org/techniques/T1222/002/), [T1070.006](https://attack.mitre.org/techniques/T1070/006/), [T1497](https://attack.mitre.org/techniques/T1497/)).| APT32 uses a script to remove flags the operating system uses for additional security protocols (ex. bypassing gatekeeper checks). <sup> 4 </sup> </p> APT32 has anti-debug and anti-sandbox functionality. If a debugger is detected, APT32 attempts to detach it by calling ptrace with PT_DENY_ATTACH as a request parameter. <sup> 6 </sup> </p> Prior to exfiltration, APT32 uses a combination of byte scrambling and AES encryption on the collected data. The AES256 key is also scrambled using XOR and ROL 6. <sup> 7 </sup> APT32 changes the permission of a file it wants to execute to 755. <sup> 7 </sup> </p> Upon installation, APT32’s second-stage payload modifies the timestamp of the backdoor files using the “touch” command. <sup> 5, 6, 7 </sup>
|2| Once APT32 has compromised the target machine, it employs lateral movement to move to the internal Linux server using SSH keys ([T1021.004](https://attack.mitre.org/techniques/T1021/004/)) and known_hosts ([T1018](https://attack.mitre.org/techniques/T1018/)). APT32 performs credential dumping using uploaded tools to escalate their privileges ([T1003](https://attack.mitre.org/techniques/T1003/), [T1105](https://attack.mitre.org/techniques/T1105/)).| The attacker performs network scanning to determine open ports, services, OS fingerprinting and vulnerabilities in the target machine. <sup> 11 </sup>



# References
[1] [OceanLotus Blossoms: Mass Digital Surveillance and Attacks Targeting ASEAN, Asian Nations, the Media, Human Rights Groups, and Civil Society](https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/)  </br>
[2] [OceanLotus: Extending Cyber Espionage Operations Through Fake Websites](https://www.volexity.com/blog/2020/11/06/oceanlotus-extending-cyber-espionage-operations-through-fake-websites/) </br>
[3] [The New and Improved macOS Backdoor from OceanLotus](https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/)</br>
[4] [APT32 Multi-stage macOS Trojan Innovates on Crimeware Scripting Technique](https://www.sentinelone.com/labs/apt32-multi-stage-macos-trojan-innovates-on-crimeware-scripting-technique/) </br>
[5] [New MacOS Backdoor Connected to OceanLotus Surfaces](https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html)</br>
[6] [OceanLotus: macOS malware update](https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/) </br>
[7] New MacOS Backdoor Linked to OceanLotus Found - New MacOS Backdoor Linked to OceanLotus Found </br>
[8] Operation Cobalt Kitty: Attackers’ Arsenal - https://www.cybereason.com/hubfs/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty-Part2.pdf </br>
[9] RotaJakiro: A long live secret backdoor with 0 VT detection - RotaJakiro: A long live secret backdoor with 0 VT detection </br>
[10] Operation Cobalt Kitty: A large-scale APT in Asia carried out by the OceanLotus Group - Operation Cobalt Kitty: A large-scale APT in Asia carried out by the OceanLotus Group </br>
[11] Operation Cobalt Kitty: Attack Lifecycle - https://www.cybereason.com/hubfs/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty-Part1.pdf </br>
[12] Cyber Espionage is Alive and Well: APT32 and the Threat to Global Corporations - Cyber Espionage is Alive and Well: APT32 and the Threat to Global Corporations | Mandiant </br>
[13] OceanLotus: New watering hole attack in Southeast Asia - OceanLotus: New watering hole attack in Southeast Asia </br>
[14] The New and Improved macOS Backdoor from OceanLotus - https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/ </br>
[15] RotaJakiro, the Linux version of the OceanLotus - RotaJakiro, the Linux version of the OceanLotus </br>
[16] OceanLotus APT Hits Human Rights Orgs in Vietnam, China, Cambodia - OceanLotus APT Hits Human Rights Orgs in Vietnam, China, Cambodia </br>
