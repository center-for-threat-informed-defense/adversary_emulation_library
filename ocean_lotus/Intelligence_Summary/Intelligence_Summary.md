# OceanLotus Intelligence Summary

An overview of the adversary and references to cited Intelligence.

**Objectives:** [OceanLotus](https://attack.mitre.org/groups/G0050/) is thought to be a
highly selective and well-resourced cyber threat actor whose objectives align with the
interests of the Vietnamese government. This group is reported to have been operating
since 2012 and may have logged operational successes as recently as
2022.<sup>[1](https://www.joesandbox.com/analysis/690250/0/html)</sup> OceanLotus'
objective over time and across a diverse target set appears to have been the
exfiltration of information that could be used to advance Vietnamese capabilities,
suppress pro-democratic influencers, and inform strategic decision
making.<sup>[2](https://blogs.360.cn/post/oceanlotus-apt.html)
[3](https://www.mandiant.com/resources/blog/cyber-espionage-apt32)
[4](https://www.amnestyusa.org/wp-content/uploads/2021/02/Click-and-Bait_Vietnamese-Human-Rights-Defenders-Targeted-with-Spyware-Attacks.pdf)</sup>

**Target Industries:** OceanLotus operations have been directed against private
corporations in the manufacturing, consumer product, and hospitality sectors. As well as
foreign governments, political dissidents, and journalists with pro-democratic rhetoric.
Geographically, OceanLotus targets the Philippines, Cambodia, Laos, Australia, Germany,
US, and inside of
Vietnam.<sup>[3](https://www.mandiant.com/resources/blog/cyber-espionage-apt32)
[5](https://www.abc.net.au/news/2018-05-15/hackers-trigger-software-trap-after-phnom-penh-post-sale/9763906)</sup>

**Operations:** In terms of operational tradecraft, OceanLotus is distinguished by their highly targeted operations and continued development on file-less and modularized capabilities. OceanLotus is reported to have exploited zero-day vulnerabilities and has pursued actions on the objective using suites of custom malware, coupled with alternate execution methods such as Cobalt Strike, a customized Outlook C2, perl, and bash scripting.<sup>[6](https://www.cybereason.com/hubfs/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty-Part1.pdf) [7](https://www.trendmicro.com/en_vn/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html)</sup>

OceanLotus is reported to attain initial access using drive-by compromise
([T1189](https://attack.mitre.org/techniques/T1189/)) and phising
([T1566.001](https://attack.mitre.org/techniques/T1566/001),
[T1566.002](https://attack.mitre.org/techniques/T1566/002/)).<sup>[8](https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/)</sup>
Once an initial foothold is established, OceanLotus often establishes persistence
through creating a system service
([T1569](https://attack.mitre.org/techniques/T1569/)).<sup>[6](https://www.cybereason.com/hubfs/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty-Part1.pdf)
[9](https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/)
[10](https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/)</sup>

OceanLotus has been reported to use the
[OSX.OceanLotus](https://attack.mitre.org/software/S0352/) backdoor as a
post-exploitation tool first reported in 2017 and last reported in 2020. A significant
characteristic of this software is it's modularized capability, leveraging dynamic
library files (.dylib files) to manage the network communications and additional plugin
capabilities.<sup>[7](https://www.trendmicro.com/en_vn/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html)
[10](https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/)
</sup> In 2020, a Linux backdoor was discovered and named Rota Jakiro. Researchers found
this implant had been undetected for three years. Based on community engagement,
researchers were able to attribute the Rota Jakiro backdoor to the OceanLotus group.
This software follows the same modularized structure as the OSX.OceanLotus software.
However, rather than .dylib files Rota Jakiro leverages shared object files (.so) to
manage plugin
functionality.<sup>[9](https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/)</sup>
<sup>[11](https://blog.netlab.360.com/rotajakiro_linux_version_of_oceanlotus/)</sup>


**Associated Groups:** APT32, SeaLotus, APT-C-00, Ocean Buffalo

## Group Overview Report References
| Source ID | Report Links                                                                                                                                                       |
| :-------: | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|     1     | https://www.joesandbox.com/analysis/690250/0/html                                                                                                                  |
|     2     | https://blogs.360.cn/post/oceanlotus-apt.html                                                                                                                      |
|     3     | https://www.mandiant.com/resources/cyber-espionage-apt32                                                                                                           |
|     4     | https://www.amnestyusa.org/wp-content/uploads/2021/02/Click-and-Bait_Vietnamese-Human-Rights-Defenders-Targeted-with-Spyware-Attacks.pdf                           |
|     5     | https://www.abc.net.au/news/2018-05-15/hackers-trigger-software-trap-after-phnom-penh-post-sale/9763906                                                            |
|     6     | https://www.cybereason.com/hubfs/Cybereason%20Labs%20Analysis%20Operation%20Cobalt%20Kitty-Part1.pdf                                                               |
|     7     | https://www.trendmicro.com/en_vn/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html                                                            |
|     8     | https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/ |
|     9     | https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/                                                                                                        |
|    10     | https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/                                                                                 |
|    11     | https://blog.netlab.360.com/rotajakiro_linux_version_of_oceanlotus/                                                                                                |


## Connect with us 🗨️
We 💖 feedback! Let us know how using this plan has helped you and what we can do better.

Email: ctid@mitre-engenuity.org <br>
Twitter: https://twitter.com/MITREengenuity <br>
LinkedIn: https://www.linkedin.com/company/mitre-engenuity/
