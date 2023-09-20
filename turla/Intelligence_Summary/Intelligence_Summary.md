# Turla Intelligence Summary
## ATT&CK Group ID: [G0010](https://attack.mitre.org/groups/G0010/)

Active since at least the early 2000s, [Turla](https://attack.mitre.org/groups/G0010/) is a sophisticated Russian-based threat group that has exploited victims in more than 50 countries.<sup>[1](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a)</sup> The group has targeted government agencies, diplomatic missions, military groups, research and education facilities, critical infrastructure sectors, and media organizations.<sup>[1](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a)</sup> <sup>[2](https://www.justice.gov/opa/pr/justice-department-announces-court-authorized-disruption-snake-malware-network-controlled)</sup>  [Turla](https://attack.mitre.org/groups/G0010/) leverages novel techniques and custom tooling and open-source tools to elude defenses and persist on target networks. <sup>[3](https://www.hhs.gov/sites/default/files/major-cyber-orgs-of-russian-intelligence-services.pdf)</sup> <sup>[4](https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_TURLA_20191021%20VER%203%20-%20COPY.PDF)</sup> The group is also known for its adaptability and willingness to evolve behaviors and tools to achieve campaign objectives. <sup>[5](https://www.eset.com/us/about/newsroom/press-releases/cyber-espionage-group-turla-and-its-latest-malware-under-the-microscope-1/)</sup> <sup>[6](https://www.kaspersky.com/about/press-releases/2023_apt-q1-2023-playbook-advanced-techniques-broader-horizons-and-new-targets)</sup> <sup>[7](https://www.ncsc.gov.uk/static-assets/documents/Turla%20Neuron%20Malware%20Update.pdf)</sup>
[Turla](https://attack.mitre.org/groups/G0010/) is known for their targeted intrusions and innovative stealth. After establishing a foothold and conducting victim enumeration, [Turla](https://attack.mitre.org/groups/G0010/) persists with a minimal footprint through in-memory or kernel implants. <sup>[8](https://cert.gov.ua/article/5213167)</sup> <sup>[9](https://dl.acm.org/doi/pdf/10.1145/3603506)</sup> [Turla](https://attack.mitre.org/groups/G0010/) executes highly targeted campaigns aimed at exfiltrating sensitive information from Linux and Windows infrastructure.<sup>[10](https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf)</sup> <sup>[11](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf)</sup>

**Associated Groups:** IRON HUNTER, Group 88, Belugasturgeon, Waterbug, WhiteBear, Snake, Krypton, Venomous Bear

## Technique Scope


## Key Adversary Report References
Source ID | Report Links
|:---:|:---|
|1|https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a|
|2|https://www.justice.gov/opa/pr/justice-department-announces-court-authorized-disruption-snake-malware-network-controlled|
|3|https://www.hhs.gov/sites/default/files/major-cyber-orgs-of-russian-intelligence-services.pdf|
|4|https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_TURLA_20191021%20VER%203%20-%20COPY.PDF|
|5|https://www.eset.com/us/about/newsroom/press-releases/cyber-espionage-group-turla-and-its-latest-malware-under-the-microscope-1/|
|6|https://www.kaspersky.com/about/press-releases/2023_apt-q1-2023-playbook-advanced-techniques-broader-horizons-and-new-targets|
|7|https://www.ncsc.gov.uk/static-assets/documents/Turla%20Neuron%20Malware%20Update.pdf|
|8|https://cert.gov.ua/article/5213167|
|9|https://dl.acm.org/doi/pdf/10.1145/3603506|
|10|https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf|
|11|https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf|
|12|https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf|
|13|https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/|
|14|https://blog.talosintelligence.com/tinyturla/|
|15|https://www.leonardo.com/documents/15646808/16757471/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf/524e39d0-029f-1a99-08d5-c013be1b8717?t=1590739252338|
|16|https://www.gdatasoftware.com/blog/2015/01/23926-analysis-of-project-cobra|
|17|https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/waterbug-espionage-governments|
|18|https://www.gdatasoftware.com/blog/2014/03/23966-uroburos-deeper-travel-into-kernel-protection-mitigation|
|19|https://unit42.paloaltonetworks.com/acidbox-rare-malware/|
|20|https://securelist.com/analysis/publications/65545/the-epic-turla-operation/|
|21|https://www.lastline.com/labsblog/turla-apt-group-gives-their-kernel-exploit-a-makeover/|
|22|https://www.justice.gov/opa/pr/justice-department-announces-court-authorized-disruption-snake-malware-network-controlled|
|23|https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-129a|
|24|https://www.hhs.gov/sites/default/files/major-cyber-orgs-of-russian-intelligence-services.pdf|
|25|https://media.defense.gov/2019/Oct/18/2002197242/-1/-1/0/NSA_CSA_TURLA_20191021%20VER%203%20-%20COPY.PDF|
|26|https://www.eset.com/us/about/newsroom/press-releases/cyber-espionage-group-turla-and-its-latest-malware-under-the-microscope-1/|
|27|https://www.kaspersky.com/about/press-releases/2023_apt-q1-2023-playbook-advanced-techniques-broader-horizons-and-new-targets|
|28|https://www.ncsc.gov.uk/static-assets/documents/Turla%20Neuron%20Malware%20Update.pdf|
|29|https://cert.gov.ua/article/5213167|
|30|https://dl.acm.org/doi/pdf/10.1145/3603506|
|31|https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf|

## Connect with us 🗨️
We 💖 feedback! Let us know how using ATT&CK Evaluation results has helped you and what we can do better.

Email: evals@mitre-engenuity.org
Twitter: https://twitter.com/MITREengenuity
LinkedIn: https://www.linkedin.com/company/mitre-engenuity/
