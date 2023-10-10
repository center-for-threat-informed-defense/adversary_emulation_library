# menuPass Operations Flow

Please see the formal [menuPass Intelligence Summary](/menuPass/Intelligence_Summary.md) which includes a break-down of the cited intelligence used for each step of this emulation.  The menuPass emulation is split into two distinct Scenarios, [Scenario 1](/menuPass/Emulation_Plan/Scenario1.md) and [Scenario 2](/menuPass/Emulation_Plan/Scenario2.md).

---

![/menuPass/Emulation_Plan/OpFlow_Diagram.png](/menuPass/Emulation_Plan/OpFlow_Diagram.png)

---

# Reconnaissance and Resource Development

Due to the wealth of publicly available information in this regard, reconnaissance and resource development considerations have been summarized.  While not necessary, if you have the resources to emulate this activity and intend to do so while remaining operationally representative, the information provided may be beneficial.  Information gathering, capability development, weaponization, and infrastructure are discussed at a high level to give context to the emulation and serve as a reference for the emulation team.

# Scenario 1

Scenario 1 prescribes TTPs similar to those attributed to menuPass specific to the group's efforts targeting MSP subscriber networks.

menuPass is reported to have compromised MSP networks with the intent of abusing trust relationships to pivot into subscriber networks.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup>  The attackers traversed MSP networks in search of shared infrastructure.  This infrastructure was compromised and used as a pivot point into the subscriber network.  menuPass is commonly reported to have accessed subscriber networks with legitimate but compromised MSP or subscriber domain credentials.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup>

## Initial Access
To emulate initial access, you may elect to assess the feasibility of trusted relationship abuse by enumerating shared infrastructure and services that could serve as a foothold into your networks.

You may also assume breach by providing the emulation team with a VPN/RDP connection.  menuPass is reported to have initially accessed MSP subscriber networks with elevated permissions, so too should the emulation team.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup>  The intent of this scenario is to assess your organization's ability to protect, detect, and defend against execution, tool ingress, discovery, credential access, lateral movement, persistence, collection, and exfiltration and thereby encourage defense in depth.  The YAML file does not address initial access.  This procedure is left to the discretion of the emulation team.

## Tool Ingress

After establishing a point of presence on the target network, menuPass actors are commonly reported to have introduced an operational toolkit from attacker controlled infrastructure.  This operational toolkit enables the attackers to pursue operational objectives and will enable the emulation team to pursue the subsequent steps in this scenario.

## Discovery

Once the operational toolkit has been introduced to the operating environment, the emulation team will conduct discovery with the intent of identifying opportunities while attempting to blend in with routine administrative tasks.  The emulation team should enumerate the network and Active Directory (AD) with the intent of identifying opportunities for credential access and lateral movement.  This is also the time to begin searching for systems of interest and identifying approaches to these systems.

## Credential Access

This objective should be pursued in parallel with discovery.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  Reporting suggests that the credentials used by menuPass to pivot into target networks provided elevated permissions.  Other reporting details menuPass's use of exploits to achieve initial access.  Some of these exploits may have resulted in code execution in an elevated context.  In either case, the need for privilege escalation has been satisfied and the actors may instead, be interested in pursuing credential access in order to ensure freedom of movement throughout the domain.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  menuPass actors are thought to have compromised additional credentials using publicly available tools like Mimikatz and Secretsdump.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>

## Lateral Movement

After performing discovery and compromising additional credentials, the emulation team should attempt lateral movement to systems of interest using tools indicative of routine administrative tasks.

menuPass is reported to have accessed remote systems by mounting remote network shares, using RDP to console into remote machines, and by using tools like PsExec to achieve remote code execution.  menuPass actors are reported to have used these techniques to deploy their sustained malware to remote systems and subsequently establish C2.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  After C2 was established with the system of interest, menuPass actors are reported to have confirmed network connectivity and conducted situational awareness checks.

## Collection and Staging

After successfully establishing a point of presence on the remote system of interest, menuPass actors are then reported to have browsed the file system in search of information.  This information was subsequently compressed and staged for exfiltration, often in the Recycle Bin.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>

## Exfiltration

The compressed archives are then reported to have been exfiltrated from the victim network by mounting a remote network share and copying the files out of the network or by using tools like Putty and/or Robocopy to transfer the data.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>

---

# Scenario 2

Scenario 2 prescribes TTPs publicly attributed to menuPass that entail the pursuit of operational objectives using a command-and-control framework.  This scenario is intended to assess your organization's ability to protect, detect, and defend to execution, discovery, privilege escalation, credential access, lateral movement, exfiltration, command and control, and persistence using a C2 framework.  Amongst other tactical implants, menuPass is reported to have used Koadic C3.  This publicly available C2 framework relies on Windows Scripting Host to conduct most of its operations.  This tool will be used to pursue tactical objectives with the operational objective of exfiltrating/simulating exfiltration.

## Initial Access

menuPass is reported to have deployed tactical implants by spearphishing.  Spearphishing emails attributed to menuPass typically featured a weaponized attachment that when opened, would exploit a vulnerability, direct the recipient to run an embedded macro, or click a link to download and execute a file.  Each of these vectors were responsible for deploying menuPass malware and establishing command and control.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>

## Execution

If you have the resources to dedicate to emulating a phishing campaign, please do so.  We have suggested an execution event that situates a tactical implant (Koadic C3) in memory and establishes C2.  This implant will be used to accomplish the subsequent steps in this scenario.

## Discovery

After establishing C2, menuPass actors are reported to have conducted situational awareness checks by accessing the Windows command-line.  You may also elect to conduct discovery with the intent of identifying systems of interest, staging points, and viable points of persistence.

## Privilege Escalation

In the event that the assessing team is unable to escalate privileges, this event can be “white-carded” with the granting of administrative rights to the compromised account.  This white-carded event could enable the assessing team to escalate via credential access, as most of the credential access procedures described hereafter require elevated privileges.  You may also elect to use Koadic's "elevate" modules to achieve execution in an elevated context.

## Credential Access

Much like Scenario 1, we will seek to access additional credentials to ensure freedom of movement.  This step differs from credential access in Scenario 1 as we will be using our tactical implant to achieve credential access.

In some instances, menuPass actors are reported to have copied and exfiltrated the Active Directory database file (NTDS.dit). This level of credential access ensures freedom of movement throughout the domain.

## Lateral Movement and Exfiltration

The credentials used in the previous step will be coupled with modules native to Koadic to move laterally to systems of interest and conduct exfiltration/simulate exfiltration.

## C2 and Persistence

menuPass is reported to have deployed sustained malware to strategic systems within the compromised environment to ensure long-term persistent access to the network.<sup>[4](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup> <sup>[5](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)</sup> <sup>[6](https://www.justice.gov/opa/press-release/file/1121706/download)</sup> <sup>[7](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</sup> <sup>[10](https://recordedfuture.com/apt10-cyberespionage-campaign/)</sup> <sup>[12](https://us-cert.cisa.gov/ncas/alerts/TA17-117A)</sup>  In this step, we use Koadic and/or the Windows command-line to ingress sustained malware.  menuPass is widely reported to have used the publicly available QuasarRat.

---

## Additional Plan Resources

- [Intelligence Summary](/menuPass/Intelligence_Summary.md)
- [Operations Flow](/menuPass/Operations_Flow.md)
- [Emulation Plan](/menuPass/Emulation_Plan/README.md)
  - [Resource Development](/menuPass/Emulation_Plan/ResourceDevelopment.md)
  - [Infrastructure](/menuPass/Emulation_Plan/Infrastructure.md)
  - [Scenario 1](/menuPass/Emulation_Plan/Scenario1.md)
  - [Scenario 2](/menuPass/Emulation_Plan/Scenario2.md)
  - [YAML](/menuPass/Emulation_Plan/yaml)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/menuPass/CHANGE_LOG.md)
