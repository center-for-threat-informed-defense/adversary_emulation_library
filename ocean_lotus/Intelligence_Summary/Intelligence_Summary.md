# OceanLotus Intelligence Summary
## ATT&CK Group ID: [G0050](https://attack.mitre.org/groups/G0050/)

**Objectives:** [OceanLotus](https://attack.mitre.org/groups/G0050/) is a cyber threat actor whose campaigns align with Vietnamese state interests. It's believed they began operations in 2014. <sup>[1](https://www.mandiant.com/resources/cyber-espionage-apt32)</sup> Their objectives include mass surveillance, reconnaissance, and data exfiltration. <sup>[2](https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/)</sup> <sup>[3](https://www.recordedfuture.com/apt32-malware-campaign/)</sup>

**Target Industries:** OceanLotus targets private corporations in the manufacturing, consumer product, and hospitality sectors as well as foreign governments, political dissidents, and journalists. Specifically, between February 2018 and November 2020, the threat actors launched several spyware attacks against Vietnamese human rights activists, bloggers, and nonprofit organizations, believed to be a result of the government's efforts to censor pro-democratic rhetoric. <sup>[4](https://www.amnestyusa.org/wp-content/uploads/2021/02/Click-and-Bait_Vietnamese-Human-Rights-Defenders-Targeted-with-Spyware-Attacks.pdf)</sup> Reporting indicates OceanLotus targets Vietnam, Philippines, Cambodia, Laos, Australia, Germany, and the US. <sup>[5](https://www.abc.net.au/news/2018-05-15/hackers-trigger-software-trap-after-phnom-penh-post-sale/9763906)</sup> <sup>[6](https://adversary.crowdstrike.com/en-US/adversary/ocean-buffalo/)</sup>

**Operations:** OceanLotus tradecraft includes being adept at compromising multiple operating systems, creating fake or compromised websites aimed at their targets, and a willingness to modify their behavior and tooling in support of their objectives. OceanLotus uses drive-by compromise and phishing as initial attack vectors. While they originally targeted Windows operating systems, in 2017 a macOS backdoor was identified and then in 2020 a new variant of that backdoor along with a Linux version was discovered. Notably, the Linux version was written back in 2018 but evaded detection until about 2020. <sup>[7](https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/)</sup> <sup>[8](https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/)</sup>

OceanLotus reporting indicates initial access occurs via phishing ([T1566](https://attack.mitre.org/techniques/T1566/)), drive-by compromise ([T1189](https://attack.mitre.org/techniques/T1189/)), and stage capabilities ([T1608](https://attack.mitre.org/techniques/T1608/)) if OceanLotus has either created their own or compromised an existing site. <sup>[9](https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/)</sup> Once an initial foothold is established, OceanLotus establishes persistence by creating or modifying system processes ([T1543](https://attack.mitre.org/techniques/T1543/)), uses masquerading to disguise their malware ([T1036.008](https://attack.mitre.org/techniques/T1036/008/)), does discovery by checking files and system information ([T1083](https://attack.mitre.org/techniques/T1083/), [1082](https://attack.mitre.org/techniques/T1082/)) , and then moves laterally ([TA0008](https://attack.mitre.org/tactics/TA0008/)) to other systems. <sup>[7](https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/)</sup> <sup>[8](https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/)</sup> <sup>[10](https://www.cybereason.com/hubfs/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty-Part1.pdf)</sup>

Associated Groups: APT32, SeaLotus, APT-C-00, Ocean Buffalo

## Technique Scope
![OceanLotus Technique Scope](../Intelligence_Summary/attack_navigator_TTPs.png/)

## Group Overview Report References
Source ID | Report Links
|:---:|:---:|
|1|https://www.mandiant.com/resources/cyber-espionage-apt32|
|2|https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/|
|3|https://www.recordedfuture.com/apt32-malware-campaign/|
|4|https://www.amnestyusa.org/wp-content/uploads/2021/02/Click-and-Bait_Vietnamese-Human-Rights-Defenders-Targeted-with-Spyware-Attacks.pdf|
|5|https://www.abc.net.au/news/2018-05-15/hackers-trigger-software-trap-after-phnom-penh-post-sale/9763906|
|6|https://adversary.crowdstrike.com/en-US/adversary/ocean-buffalo/|
|7|https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/|
|8|https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/|
|9|https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/|
|10|https://www.cybereason.com/hubfs/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty-Part1.pdf|

## Connect with us 🗨️
We 💖 feedback! Let us know how using this plan has helped you and what we can do better.

Email: ctid@mitre-engenuity.org <br>
Twitter: https://twitter.com/MITREengenuity <br>
LinkedIn: https://www.linkedin.com/company/mitre-engenuity/
