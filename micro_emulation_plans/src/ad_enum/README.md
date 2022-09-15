# Micro Emulation Plan: Active Directory Enumeration

This micro emulation plan targets compound behaviors associated with [TA0007
Discovery](https://attack.mitre.org/tactics/TA0007/) using behaviors associated
with abuse of Active Directory (AD). Adversaries use various means to gather
internal knowledge about victim environments. Active directory, specifically
[Active Directory Domain Services (AD
DS)](https://docs.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview),
is often targeted as rich and accessible source of information about various
objects in a network.

**Table Of Contents:**

- [Micro Emulation Plan: Active Directory Enumeration](#micro-emulation-plan-active-directory-enumeration)
  - [Description of Emulated Behaviors](#description-of-emulated-behaviors)
  - [Cyber Threat Intel / Background](#cyber-threat-intel--background)
  - [Execution Instructions / Resources](#execution-instructions--resources)
    - [Execution Demo](#execution-demo)
  - [Defensive Lessons Learned](#defensive-lessons-learned)
    - [Detection](#detection)
    - [Mitigation](#mitigation)

## Description of Emulated Behaviors

**What are we doing?** This module provides an easy-to-execute tool for
generating queries to enumerate various types of information within an AD
environment. Execution of this module aims to produce telemetry similar (but not
identical) to the AD enumeration tools used in the wild.

The following ATT&CK v11 techniques are used in this emulation plan:

* [T1087 Account Discovery](https://attack.mitre.org/techniques/T1087)
* [T1135 Network Share Discovery](https://attack.mitre.org/techniques/T1135)
* [T1069 Permission Groups Discovery](https://attack.mitre.org/techniques/T1069)
* [T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)
* [T1049 System Network Connections Discovery](https://attack.mitre.org/techniques/T1049)
* [T1033 System Owner/User Discovery](https://attack.mitre.org/techniques/T1033)

## Cyber Threat Intel / Background

**Why you should care?** Threat actors and malware use [TA
Discovery](https://attack.mitre.org/tactics/TA0007/) to gather internal
knowledge about a victim environment that can be used to plan/shape next steps
(ex: [TA0008 Lateral Movement](https://attack.mitre.org/tactics/TA0008/) and/or
[TA0004 Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)) during
an intrusion. There are various ways an adversary can collect different types of
information, but [Active Directory
(AD)](https://docs.microsoft.com/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview)
is commonly abused given its accessibility and wealth of data spanning accounts,
hosts, services, etc. AD enumeration is very often observed as a [precursor to
the deployment of
ransomware](https://thedfirreport.com/wp-content/uploads/2022/06/SANS-Ransomware-Summit-2022-Can-You-Detect-This.pdf)
to most if not all [domain-joined
systems](https://posts.specterops.io/bloodhound-versus-ransomware-a-defenders-guide-28147dedb73b).

Various [interfaces and APIs exists to query
AD](https://docs.microsoft.com/windows/win32/ad/choosing-the-search-technology),
but threat actors often opt to abuse available tools/utilities such as
SharpHound/[S0521 BloodHound](https://attack.mitre.org/software/S0521/), [S0552
AdFind](https://attack.mitre.org/software/S0552/), [S0105
dsquery](https://attack.mitre.org/software/S0105/), and [Nltest](S0539
https://attack.mitre.org/software/S0359/). These dual-use tools may make
execution of these discovery behaviors easier for adversaries while also
potentially blending in with legitimate administrator activity.

## Execution Instructions / Resources

The `ad_enum.exe` executable invokes a series of AD enumeration queries based on
provided arguments. The [source code](ad_enum.cs) for this module is also
provided if you wish to further customize and [rebuild](BUILD.md).

The `ad_enum.exe` executable invokes a series of AD enumeration queries:

0. Query LDAP for all users, and output user information
1. Query LDAP for all users, and output their name
2. Query LDAP for all groups, and output their name, members, and memberOf attributes
3. Query LDAP for all groups containing the word `"admin"` in their name, and
   output their name, members, and memberOf attributes
4. Query LDAP for all computers on the domain
5. Query LDAP for all domain controllers on the domain
6. List information about users currently logged on to this computer via
   `NetWkstaUserEnum()`
7. List the network shares on this computer via `NetShareEnum()`
8. List the current sessions on this computer via the `query session` command

**Note:** Queries 0-5 will only work correctly on a host that is joined to a
Windows domain.

Queries can be selected by passing arguments to the executable via the `-c` /
`-command` flag (i.e. `ad_enum.exe -c 0,4,8`). A help menu is available by
running the module with `-h` or `-help`. `-m` / `-menu` will invoke an
interactive menu.

Output will be saved to a local file called `ad_enum_log.txt`. By default (no
arguments provided), the module will execute queries for options `{0, 3, 5, 7,
8}` while limiting (otherwise specified via `-l` / `-limit`) displayed results
to 20 values.

### Execution Demo

![Animated screen capture demonstrating use of the tool.](docs/adEnum.gif)

## Defensive Lessons Learned

### Detection

AD queries may generate [high-volume bursts of network
connections]((https://redcanary.com/threat-detection-report/threats/bloodhound/)),
especially to domain controllers over ports [associated with LDAP (ports 389 and
636) or RPC functions (ports 137 and
445)](https://blog.menasec.net/2019/02/threat-hunting-7-detecting.html) as well
as the creation of detectable [named pipes](../named_pipes/README.md). If
network packet capture or other comparable telemetry (including [LDAP
ETW](https://github.com/SigmaHQ/sigma/blob/33b370d49bd6aed85bd23827aa16a50bd06d691a/rules/windows/builtin/ldap/win_ldap_recon.yml))
is available, [LDAP search
filters](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726)
can be used to identify suspicious enumeration
activity:

```yaml
    telemetry:
      ldap_query:
        - EDR (Microsoft-Windows-LDAP-Client ETW)
    rules: >
      - Channel:EDR AND EventType:LDAPQuery AND QueryDN:"CN\=*" AND QueryFilter.keyword:/member\=\*/
      - Channel:EDR AND EventType:LDAPQuery AND QueryDN:"CN\=*" AND QueryFilter.keyword:/member\=\*/ AND QueryFilterAttributes.keyword:/member\;range\=0\-\*/
      - Channel:EDR AND EventType:LDAPQuery AND QueryDN:"OU\=*" AND QueryFilter:"*\(samAccountType\=805306368\)\(samAccountType\=805306369\)*"
```

*Code excerpted from [github.com/vadim-hunter/Detection-Idea-Rules](https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Tools/BloodHound.yaml)*

Although not directly associated with the discovery behaviors, various AD
enumeration tools commonly abused by adversaries may [leave distinct
artifacts](https://github.com/vadim-hunter/Detection-Ideas-Rules/blob/main/Tools/BloodHound.yaml)
([such as files](https://thedfirreport.com/2022/03/07/2021-year-in-review/)) on
hosts or execute with
identifiable process/command/script
arguments:.

> **Common BloodHound command-line options**
>
> This detection analytic identifies processes that contain common command lines
> consistent with the execution of BloodHound. While this is a simple analytic,
> we’ve found it to be effective in identifying BloodHound. It’s a good
> supplement to the port 445 analytic, which can require more tuning.
>
> ```
> command_line_includes ('-collectionMethod' || 'invoke-bloodhound' || 'get-bloodHounddata')
> ```
*Excerpted from [Red Canary's BloodHound
report](https://redcanary.com/threat-detection-report/threats/bloodhound/).*

### Mitigation

Consider blocking or otherwise preventing the execution of AD enumeration
tools/utilities that are not needed within an environment. Access to AD objects
can also be managed through [policy-based access
control](https://docs.microsoft.com/windows/win32/ad/how-access-control-works-in-active-directory-domain-services).
The same dual-use tools abused by adversaries can be used to [identify and
remediate misconfigurations and/or available attack
paths](https://posts.specterops.io/bloodhound-versus-ransomware-a-defenders-guide-28147dedb73b).
Specifically, proactive measures can be taken to minimize the risks of data
available via AD enumeration by auditing:

1. Permissions against sensitive security principals (user/computer accounts and
   groups) such as (Domain) Admins, partially addressed by queries `2` and `3`
2. Privileged user activity (ex: caching sensitive credentials by logging onto
   systems), partially addressed by queries `0`, `6`, and `8`
3. Permissions against sensitive systems (ex: local admins of a computer),
   partially addressed by queries `2` through `5`

Adversary engagement activities, such as [diversifying and/or manipulating
information and properties of systems](https://engage.mitre.org/matrix/), may
present denial and deception opportunities that can be used to manipulate and
disrupt adversary enumeration activities.
