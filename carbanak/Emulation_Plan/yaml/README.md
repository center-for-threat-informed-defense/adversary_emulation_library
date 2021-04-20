# Machine-Readable Carbanak Emulation Plan

The universal, technology-agnostic version of the Carbanak emulation plan YAML has been provided as starting point for machine parsing and execution of the Carbanak emulation plan. This folder will store all versions of this yaml file, including those formatted to work with specific execution runners (such as automated agents like [CALDERA](https://github.com/mitre/caldera) or other breach simulation frameworks).

As Scenario 2 uses almost the same content as Scenario 1, but packages it into independent objectives, the YAML contains procedures linked only to the steps from Scenario 1. A table has been provided below to link the procedures within the YAML to the specific Scenario 2 steps.

## Included Formats

As new files are added, please list them in the below table.

| File | Execution Framework | Notes |
| --- | --- | --- |
| [Carbanak.yaml](/Emulation_Plan/yaml/Carbanak.yaml) | N/A | Initial Emulation Plan YAML |

---

## Skipped Procedures

A number of procedures within the emulation plan are not present within the YAML file.
This is because these procedures integrate with external frameworks or involve interaction with a GUI, which cannot be simple expressed in an automatable format.

The table below lists the steps/procedures that were skipped along with the reason why.

| Step/Procedure | Step Name/Technique | Reason |
| --- | --- | --- |
| [1](/Emulation_Plan/Scenario_1#step-1---initial-access) | Initial Access | While the initial execution of the VBE payload can be automated, the payload requires the user to click 'OK' on a dialog box in order for the payload to complete successfully. |
| [2.A](/Emulation_Plan/Scenario_1#2a---local-discovery-t1033-t1082-t1057) | Local Discovery | This procedure involves sending the command `enum-system` to the RAT through the C2 channel. |
| [2.B.2](/Emulation_Plan/Scenario_1#2b---screen-capture-t1113) | [T1041 - Exfiltration over C2 Channel](https://attack.mitre.org/techniques/T1041/) | There is currently not a technology-agnostic standard to represent uploads of files back to the C2 server. |
| [4.A.1](/Emulation_Plan/Scenario_1#4a---local-and-domain-discovery-t1083-t1018-t1069) | [T1083 - File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) | This procedure uses a native meterpreter command, `ls`. |
| [4.A.2](/Emulation_Plan/Scenario_1#4a---local-and-domain-discovery-t1083-t1018-t1069) | [T1018 - Remote System Discovery](https://attack.mitre.org/techniques/T1018/) | This procedure involves loading and running PowerView's `Get-NetComputer` command from memory. |
| [4.A.3](/Emulation_Plan/Scenario_1#4a---local-and-domain-discovery-t1083-t1018-t1069) | [T1110.003 - Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) | This procedure involves loading and running PowerView's `Find-LocalAdminAccess` command from memory. |
| [5.C.2](/Emulation_Plan/Scenario_1#5c---lateral-movement-via-psexec--pass-the-hash-t1569002-t1550) | [T1021.002 - Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) | This procedure uses PsExec functionality to mount an SMB share, which is not easily replicated. |
| [6.A.2](/Emulation_Plan/Scenario_1#6a---remote-system-discovery-t1018-t1087002) | [T1087.002 - Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/) | This procedure involves loading and running PowerView's `Get-NetUser` command from memory. |
| [7.A.2](/Emulation_Plan/Scenario_1#7a---rdp-through-reverse-ssh-tunnel-t1572-t1021001) | [T1021.001 - Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/) | The lateral movement in this procedure uses RDP. GUI interaction is not supported. |
| [7.B.2](/Emulation_Plan/Scenario_1#7b---lateral-movement-to-cfo-via-rdp-t1021001) | [T1021.001 - Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001/) | The lateral movement in this procedure uses RDP. GUI interaction is not supported. |
| [8](/Emulation_Plan/Scenario_1#step-8---execution) | Legitimate CFO Login | This step involves a legitimate user logging in and performing various actions. |
| [9.A.2](/Emulation_Plan/Scenario_1#9a---user-monitoring---t1056001-t1113) | [T1113 - Screen Capture](https://attack.mitre.org/techniques/T1113/) | This procedure uses metasploit's `screen_spy` module. |
| [9.A.3](/Emulation_Plan/Scenario_1#9a---user-monitoring---t1056001-t1113) | Legitimate CFO Activity | This procedure involves legitimate user activity. |
| [10.A](/Emulation_Plan/Scenario_1#10a---install-vnc-persistence-t1543003-t1021005) | Install VNC Persistence | All procedures within this substep require Metasploit's `runas` module. |
| [10.B](/Emulation_Plan/Scenario_1#10b---use-vnc-persistence-t1021005) | Use VNC Persistence | All parts of this step involve GUI interaction. |

---

## Procedures to Note

Certain procedures included in the YAML have been modified or have external dependencies that are not captured within the YAML file.

The table below captures these steps/procedures.

| Step/Procedure | YAML Name | Note |
| --- | --- | --- |
| [3.B](/Emulation_Plan/Scenario_1#3b---execute-2nd-stage-rat-t1012-t1055) | Execute 2nd Stage RAT | An external C2 server needs to be configured to handle the callback from the Meterpreter payload. |
| [5.B.1](/Emulation_Plan/Scenario_1#5b---lateral-movement-via-ssh-t1021004) | SSH to bankfileserver | This procedure starts an SSH connection with `bankfileserver` from `hrmanager`. However, an agent is not placed on `bankfileserver`. In order to continue the scenario using the YAML, a new agent needs to be manually started from `bankfileserver`. |
| [5.C.1](/Emulation_Plan/Scenario_1#5c---lateral-movement-via-psexec--pass-the-hash-t1569002-t1550) | Lateral Movement to bankdc from bankfileserver | This procedure starts an interactive session with `bankdc` from `bankfileserver` using `psexec.py`. However, an agent is not placed on `bankdc`. In order to continue the scenario using the YAML, a new agent needs to be manually started from `bankdc`. |
| [5.C.3](/Emulation_Plan/Scenario_1#5c---lateral-movement-via-psexec--pass-the-hash-t1569002-t1550) | Upload and execute Tiny.exe on bankdc | An external C2 server needs to be configured to handle the callback from the Meterpreter payload. |
| [7.C.1](/Emulation_Plan/Scenario_1#7c---registry-persistence-t1547001) | Upload JavaUpdate.exe and Create JavaUpdate.vbs on CFO | JavaUpdate.vbs is not copied using SCP as the emulation plan dictates. Instead, it is downloaded using the automation system's default download mechanism. |

---

## Scenario 2 Procedure Mapping

The procedures in the YAML are mapped directly to the steps in Scenario 1. The table below maps the procedures to the steps of Scenario 2.

| Scenario 2 Step | `procedure_step` | procedure `id` |
| --- | --- | --- |
| [1](/Emulation_Plan/Scenario_2#step-1---initial-access--collection) | 2.B.1 | `453cb643-892b-475d-8db9-df61289749f1` |
| [2](/Emulation_Plan/Scenario_2#step-2---registry-shellcode-and-discovery) | 3.A<br>3.B | `e238f1b5-a4e7-464d-82eb-36d0cc875434`<br>`50cf48b9-2076-4efc-80f1-5b8f421ecae4` |
| [3](/Emulation_Plan/Scenario_2#step-3---credential-dumping) | 4.B | `473e5707-5786-4f53-934f-22175c1059b0` |
| [4](/Emulation_Plan/Scenario_2#step-4---lateral-movement) | 5.C.3 | `7e3a8de9-edb9-4df4-beef-9577c4562420` |
| [5](/Emulation_Plan/Scenario_2#step-5---credential-access) | 9.A.1<br>9.A.4<br>9.B.1<br>9.B.2 | `5f3f7045-ae92-4a3e-8b39-35e4f8cc3038`<br>`8b2f52d8-40d8-4f70-bf9e-cb999d325958`<br>`22ddbc4f-fb5d-4785-8bc8-373da2f3e176`<br>`f3678315-cdbb-4579-b25d-f92783e5599b` |

---

## Additional Plan Resources 

- [Intelligence Summary](/Intelligence_Summary.md)
- [Operations Flow](/Operations_Flow.md)
- [Emulation Plan](/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/Emulation_Plan/Scenario_2)
  - [YAML](/Emulation_Plan/yaml)
- [File Hashes](/hashes)
- [YARA Rules](/yara-rules)
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/CHANGE_LOG.md)