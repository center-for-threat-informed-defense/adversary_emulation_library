# FIN6 Operations Flow

Please see the formal [FIN6 Intelligence Summary](/fin6/Intelligence_Summary.md) which includes a break-down of the cited intelligence used for each step of this emulation.

This FIN6 emulation is split into two distinct phases, [Phase 1](/fin6/Emulation_Plan/Phase1.md) and [Phase 2](/fin6/Emulation_Plan/Phase2.md).

---

![/Emulation_Plan/OpFlow_Diagram.png](/fin6/Emulation_Plan/OpFlow_Diagram.png)

---

# Phase 1

## Initial Access

Phase 1 is the pursuit of enabling objectives, the first of which is initial access to the target network.  FIN6 appears to take a pragmatic approach toward delivery, varying techniques according to what is most likely to be successful.  It is therefore, recommended for the purpose of threat emulation, that assessors approach delivery in the same manner.

For teams that intend to emulate the threat for every stage of the kill-chain and assess their organization’s ability to protect, as well as detect and respond it may be prudent to approach this step from a red team perspective.  Conduct reconnaissance and choose a method of delivery that has the highest likelihood of successful delivery and exploitation.  For teams that are primarily interested in assessing their organization’s ability to detect and respond to FIN6 activity, it may not be worth the investment of resources.  For these assessors, it is recommended that you assume breach using the C2 framework of your choice.  FIN6 has made use of CobaltStrike and Metasploit.  Koadic C2 may be a good option to emulate the more_eggs implant.  FIN6 is reported to have maintained C2 over HTTPS.  

## Discovery

After gaining access to the target network, FIN6 enumerates the network and Active Directory (AD) environment.  The second objective of Phase 1 is to conduct internal reconnaissance.  The intent of this phase is to identify opportunities for escalation, lateral movement, systems for staging, and systems of interest for Phase 2 of the operation.  FIN6 is believed to have used AdFind for this purpose on at least one occasion.  For the purposes of emulation, we suggest AdFind but have recommended alternatives tools native to the Windows environment.  

## Privilege Escalation

The third objective of Phase 1 is to escalate privileges.  Reporting suggests the group has purchased credentials, made heavy use of credential access, and used the “getsystem” modules included in publicly available penetration testing frameworks.  FIN6 has been reported to further compromise the Windows domain by copying and exfiltrating the Active Directory database (NTDS.dit) file.  The information therein enables the group to move freely throughout the domain and pursue their Phase 2 objectives.  Privilege escalation can be challenging, it is recommended that you choose your initial target for “compromise” carefully.  In the event that the assessing team is unable to escalate privileges, this event can be “white-carded” with the granting of administrative rights to the compromised account.  This white-carded event could enable the assessing team to escalate via credential access as the procedures described herein require elevated privileges.

## Exfiltration

The terminating event for Phase 1 is exfiltration of Phase 1 data.  FIN6 has exfiltrated the text files resultant from Discovery and the NTDS.dit file harvested during Privilege Escalation by way of SSH and FTP.  These files are reported to have been pushed to FIN6 controlled infrastructure for processing and analysis.  The information ascertained enables the group to pursue their Phase 2 objectives.

---

# Phase 2

## Lateral Movement

Escalating privileges during Phase 1 may require lateral movement.  The lateral movement described in this phase is that which is executed in support of the group’s operational objectives, lateral movement to systems of interest identified during Discovery.  Using the information ascertained and the credentials obtained during Phase 1, the group deploys tools to systems of interest to begin harvesting data from the compromised environment.  These tools have evolved over time but were initially point-of-sale malware and most recently, ransomware.

## Exfiltration

The terminus of this phase and likewise, this emulation plan is the exfiltration of Phase 2 data.  FIN6 has used DNS tunneling to exfiltrate PoS data.  When targeting e-commerce sites, the group’s card skimming scripts exfiltrate payment data by using an HTTP POST to send the data to FIN6 controlled infrastructure.

---

## Additional Plan Resources

* [Intelligence Summary](/fin6/Intelligence_Summary.md)
* [Operations Flow](/fin6/Operations_Flow.md)
* [Emulation Plan](/fin6/Emulation_Plan/README.md)
  - [Infrastructure](/fin6/Emulation_Plan/Infrastructure.md)
  - [Phase 1](/fin6/Emulation_Plan/Phase1.md)
  - [Phase 2](/fin6/Emulation_Plan/Phase2.md)
  - [YAML](/fin6/Emulation_Plan/yaml/FIN6.yaml)
* [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
* [Change Log](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/fin6/CHANGE_LOG.md)
