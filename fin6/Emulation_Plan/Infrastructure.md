# Infrastructure

FIN6 infrastructure is likely comprised of distributed command and control (C2) servers and exfiltration servers.  FIN6 is reported to have conducted C2 over HTTPS.  As such, it would be wise to purchase, associate, and categorize a domain for each redirector.  [Let's Encrypt](https://letsencrypt.org) is a resource for free SSL/TLS certificates.

FIN6 uses separate servers for exfiltration.  They appear to purchase domain names that are similar/relevent to their target organization in order to blend in.  The group may very well use one server to exfiltrate Discovery data during Phase 1, and separate servers to exfiltrate PoS or payment data during Phase 2.  Specific server configuration very much depends on the C2 framework.

Detailing specific infrastructure configuration is beyond the scope of this plan.  Please consult the following resources:

---

## Infrastructure Configuration

* [Cloud-based Redirectors for Distributed Hacking](https://blog.cobaltstrike.com/2014/14/cloud-based-redirectors-for-distributed-hacking/)
* [Infrastructure for Ongoing Red Team Operations](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations)
* [HTTPS Payload and C2 Redirectors](https://bluescreenofjeff.com/2018-04-12-https-payload-and-c2-redirectors/)
* [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
* [A Deep Dive into Cobalt Strike Malleable C2](https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b)

---

## Emulation Team Systems and Tools

The following represents a bare minimum but should be operationally representative of FIN6 infrastructure and toolset:

* C2 Framework
  * [Metasploit Framework](https://metasploit.com/download)
  * [CobaltStrike](https://cobaltstrike.com/)
  * [KoadicC3](https://github.com/zerosum0x0/koadic)
* [ADFind](https://www.joeware.net/freetools/tools/adfind/index.htm)
* [7Zip](https://7-zip.org/download.html)
* [Putty/Plink/PSCP](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)
* [Windows Credential Editor](https://www.ampliasecurity.com/research/wce_v1_41beta_universal.zip)
* [PsExec](https://download.sysinternals.com/files/PSTools.zip)
* [Scraper](https://github.com/ahhh/PSSE/blob/master/Scrape-Memory-CCs.ps1)
* [DNSCat Server](https://github.com/iagox86/dnscat2.git)
* [DNSCat PowerShell Client](https://github.com/lukebaggett/dnscat2-powershell)
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
* [SimulateRansomware](https://github.com/BlackBox-CSP/SimulateRansomware)
* [PS2EXE](https://gallery.technet.microsoft.com/scriptcenter/PS2EXE-GUI-Convert-e7cb69d5)

## Command and Control (C2) Servers

* ### Metasploit

  * 1 x Kali/Metasploit Machine

* ### CobaltStrike

  * 1 x Teamserver
  * 1 x Redirector

## Exfiltration Servers

* ### Phase 1 - Exfiltration

  * SSH - After conducting internal discovery, FIN6 has been reported to stage the resulting files, compress those files, and typically exfiltrate using SSH. <sup>[3](https://www2.fireeye.com/rs/848-DID-242/images/rpt-fin6.pdf)</sup> <sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup> <sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>.  In order to emulate this activity, you will need to set up an exfiltration server that is capable of receiving SSH connections.

* ### Phase 2 - POS Exfiltration

  * DNS - FIN6 is reported to have exfiltrated POS data from compromised systems using DNS tunneling.<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup> <sup>[7](https://blog.morphisec.com/new-global-attack-on-point-of-sale-systems)</sup>  In order to emulate this use case (Phase2 Scenario 1), you will need to set up an exfiltration server that is capable of receiving DNS requests and issuing DNS responses.  We further describe how to emulate this activity using dnscat2 in Phase 2.

* ### Phase 2 - E-Commerce Exfiltration

  * HTTP - FIN6 is reported to have exfiltrated payment data resulting from it's Magecart Group 6 activity via HTTP POST.<sup>[10](https://blog.trendmicro.com/trendlabs-security-intelligence/fin6-compromised-e-commerce-platform-via-magecart-to-inject-credit-card-skimmers-into-thousands-of-online-shops/)</sup> In order to emulate this use case (Phase 2 Scenario 2), you will need to set up an exfiltration server capable of receiving HTTP POST requests.  Depending on how you intend to evaluate this scenario, a lightweight solution like Python's http.server may be appropriate.  This activity is further described in Phase 2.

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