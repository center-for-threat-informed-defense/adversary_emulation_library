# Infrastructure

menuPass actors are reported to have maintained distributed infrastructure that is often associated with dynamic-DNS or actor registered domains.  This infrastructure may have been maintained and reused across disparate operations.<sup>[4](https://pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)</sup>  menuPass infrastructure is used for phishing, command and control (C2), payload hosting/delivery, and exfiltration.

---

## Emulation Team Infrastructure

The infrastructure listed below is a recommendation, not a requirement.  We hope to capture the general structure of what is reported to have been seen being used by menuPass.  If you have the time and resources to remain true-to-form, you may elect to stand up multiple of each of these servers, ensuring that you use different service providers, and non-contiguous IP space, etc.  If you are not concerned with emulating menuPass to this degree, this level of effort is not necessary.  You could for instance, phish, serve payload, and exfil from/to the same server. The following represents a bare minimum but should be operationally representative of menuPass infrastructure and toolset:

* Redirectors
  * menuPass actors are thought to have used redirectors to proxy C2 traffic.  To remain operationally representative, you may consider establishing redirectors to relay your traffic with any of the available cloud service providers.  If you wish to maintain C2 over HTTPS, consider [Let's Encrypt](https://letsencrypt.org) for free SSL/TLS certificates.

* Phishing Servers (Optional)
  * Aside from exploiting trust relationships, menuPass is widely reported to have phished for initial access.  There are, a few ways to approach phishing.  The most resource intensive would be to stand up a phishing server.  This is not necessary to remain operationally representative but is mentioned to those interested in assessing their organization's ability to protect, detect, and defend to phishing.

* Payload Servers
  * In some instances, menuPass actors are reported to have used download cradles to fetch and execute payloads.  These download cradles request the payload from a payload server, whose purpose is simply...to serve payloads.  If you are concerned with maintaining distributed infrastructure, you may elect to set up a sever dedicated to this purpose.

* Exfiltration Servers
  * menuPass actors have been observed staging, compressing, and exfiltrating data from target networks.  Data is commonly reported to have been "pushed" from the network.  To emulate this activity, you will need to establish an exfiltration server that is capable of receiving connections from tools like PuTTY/PSCP.

---

## Emulation Team Infrastructure Configuration

Detailing specific infrastructure configuration is beyond the scope of this plan. Please consult the following resources:

* [Cloud-based Redirectors for Distributed Hacking](https://blog.cobaltstrike.com/2014/14/cloud-based-redirectors-for-distributed-hacking/)
* [Infrastructure for Ongoing Red Team Operations](https://blog.cobaltstrike.com/2014/09/09/infrastructure-for-ongoing-red-team-operations)
* [HTTPS Payload and C2 Redirectors](https://bluescreenofjeff.com/2018-04-12-https-payload-and-c2-redirectors/)
* [Red Team Infrastructure Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
* [A Deep Dive into Cobalt Strike Malleable C2](https://posts.specterops.io/a-deep-dive-into-cobalt-strike-malleable-c2-6660e33b0e0b)

---

## Emulation Team Systems and Tools

The tools listed hereafter are reported to have been used by menuPass, hence their inclusion in our plan.  In most cases, the exact command-line implementation of the tool is an educated guess.  These tools are recommendations, not requirements.  Our intent is to encourage a defensive posture that is informed by TTPs, not by tools.  Please feel free to use whatever toolset best suits your use case.

  * C2 Framework
    * [Koadic](https://github.com/zerosum0x0/koadic)
  * Implants
    * [Quasar](https://github.com/quasar/Quasar)
  * [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
  * [Wmiexec](https://github.com/Twi1ight/AD-Pentest-Script/blob/master/wmiexec.vbs)
  * Impacket
    * [Secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)
    * [Atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
    * [Psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)
  * [PyInstaller](https://pyinstaller.org)
  * Impacket Binaries - alternative to compiling the above python scripts with PyInstaller
    * [Compiled](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.22.dev-binaries)
  * [Nbtscan](https://unixwiz.net/tools/nbtscan.html)
  * [Netsess](https://joeware.net/freetools/tools/netsess)
  * [Mimikatz](https://github.com/gentilkiwi/mimikatz/releases)
  * [Tcping](https://elifulkerson.com/projects/tcping.php)
  * [Winrar](https://rarlab.com) (optional)
  * [PuTTY/PSCP](https://chiark.greenend.org.uk/~sgtatham/putty/latest.html)
  * [cURL](https://curl.haxx.se/windows)

---

## Target Infrastructure

Much of the publicly reported menuPass activity has been directed against Windows Domains.  This plan was designed accordingly.  To execute this plan, you will require at a minimum, the following:

* 1 Domain controller
* 2 Workstations
* 2 Servers
* Multiple accounts with varying levels of privilege

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
