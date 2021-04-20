# Machine-Readable FIN7 Emulation Plan

The universal, technology-agnostic version of the FIN7 emulation plan YAML has been provided as starting point for machine parsing and execution of the FIN7 emulation plan. This folder will store all versions of this yaml file, including those formatted to work with specific execution runners (such as automated agents like [CALDERA](https://github.com/mitre/caldera) or other breach simulation frameworks).

As Scenario 2 uses almost the same content as Scenario 1, but packages it into independent objectives, the YAML contains procedures linked only to the steps from Scenario 1. A table has been provided below to link the procedures within the YAML to the specific Scenario 2 steps.

## Included Formats

As new files are added, please list them in the below table.

| File | Execution Framework | Notes |
| --- | --- | --- |
| [Fin7.yaml](/fin7/Emulation_Plan/yaml/fin7.yaml) | N/A | Initial Emulation Plan YAML |

---

## Skipped Procedures

A number of procedures within the emulation plan are not present within the YAML file.
This is because these procedures integrate with external frameworks or involve interaction with a GUI, which cannot be simple expressed in an automatable format.

The table below lists the steps/procedures that were skipped along with the reason why.

| Step/Procedure | Step Name/Technique | Reason |
| --- | --- | --- |
| [1.A](/fin7/Emulation_Plan/Scenario_1#1a---user-execution-malicious-file-with-licensed-microsoft-word-t1204002) | [User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) | While the initial execution of the VBE payload can be automated, the payload requires the user to click 'OK' on a dialog box in order for the payload to complete successfully. |
| [2.A](/fin7/Emulation_Plan/Scenario_1#2a---sqlrat-execution-via-scheduled-task-t1053005) | SQLRat Execution via Scheduled Task | This procedure involves sending the command `get-mac-serial` to the RAT through the C2 channel. |
| [2.B](/fin7/Emulation_Plan/Scenario_1#2b---upload-powershell-stager) | Upload Powershell Stager | This procedure involves sending an upload command to the RAT through the C2 channel. |
| [3.A](/fin7/Emulation_Plan/Scenario_1#3a---discovery-t1057-t1135-t1497-t1033-t1082-t1016) | Discovery | This procedure involves sending the command `enum-system` to the RAT through the C2 channel. |
| [8.A](/fin7/Emulation_Plan/Scenario_1#8a---user-monitoring-t1055-t1113-t1055-t1056001) | User Monitoring | This procedure relies on a Metasploit module. |
| [10.B.3](/fin7/Emulation_Plan/Scenario_1#10b---obtain-credit-card-data-t1055-t1071001-t1573) | Exfiltrate Credit Card Data | There is currently not a technology-agnostic standard to represent uploads of files back to the C2 server. |

---

## Procedures to Note

Certain procedures included in the YAML have been modified or have external dependencies that are not captured within the YAML file.

The table below captures these steps/procedures.

| Step/Procedure | YAML Name | Note |
| --- | --- | --- |
| [4.A](/fin7/Emulation_Plan/Scenario_1#4a---staging-interactive-toolset-t1086) | Execution of stager.ps1 | An external C2 server needs to be configured to handle the callback from the Meterpreter payload. |
| [6.A](/fin7/Emulation_Plan/Scenario_1#6a---expand-access-t1105-t1059003-t1078002-t1021002-t1569002-t1055012) | Expand Access | An external C2 server needs to be configured to handle the callback from the Meterpreter payload. |
| [7.A](/fin7/Emulation_Plan/Scenario_1#7a---boostwrite-t1105-t1036005-t1059003-t1574001-t1071001-t1573002) | Privilege Escalation | An external C2 server needs to be configured to handle the callback from the Meterpreter payload. |
| [10.A](/fin7/Emulation_Plan/Scenario_1#10a---execute-shim-persistence-t1138) | Execute Application Shim Persistence | An external C2 server needs to be configured to handle the callback from the Meterpreter payload. |

---

## Scenario 2 Procedure Mapping

The procedures in the YAML are mapped directly to the steps in Scenario 1. The table below maps the procedures to the steps of Scenario 2.

| Scenario 2 Step | `procedure_step` | procedure `id` |
| --- | --- | --- |
| [1](/fin7/Emulation_Plan/Scenario_2/README.md#step-1---initial-access-with-embedded-vbs-in-word-document) | N/A | N/A (All procedures skipped in YAML) |
| [2](/fin7/Emulation_Plan/Scenario_2/README.md#step-2---uac-bypass-and-credential-dumping) | 5.A.1<br>5.A.2 | `ab937ef4-7c66-4349-ad3b-658c41fcf4c5`<br>`b15d3014-a5d1-4ec6-934b-d7fe44451192` |
| [3](/fin7/Emulation_Plan/Scenario_2/README.md#step-3---lateral-movement-via-pass-the-hash) | 6.A | `9a76889c-9518-4b3e-9c87-6618156015c6` |
| [4](/fin7/Emulation_Plan/Scenario_2/README.md#step-4---dll-hijacking) | 7.A | `ab48e12f-def0-40a4-b3d9-ad958f45202a` |
| [5](/fin7/Emulation_Plan/Scenario_2/README.md#step-5---shim-persistence) | 9.B<br>10.A | `eb99abcb-93e2-4a3e-bf05-a484839dc851`<br>`6ec6561b-e535-4fe3-9c20-a52e5982b513` |

---

## Additional Plan Resources 

- [Intelligence Summary](/fin7/Intelligence_Summary.md)
- [Operations Flow](/fin7/Operations_Flow.md)
- [Emulation Plan](/fin7/Emulation_Plan)
  - [Scenario 1 - Infrastructure](/fin7/Emulation_Plan/Scenario_1/Infrastructure.md)
  - [Scenario 1 - Detections](/fin7/Emulation_Plan/Scenario_1)
  - [Scenario 2 - Infrastructure](/fin7/Emulation_Plan/Scenario_2/Infrastructure.md)
  - [Scenario 2 - Protections](/fin7/Emulation_Plan/Scenario_2)
  - [YAML](/fin7/Emulation_Plan/yaml)
- [File Hashes](/fin7/hashes)
- [YARA Rules](/fin7/yara-rules)
- [Issues](/issues)
- [Change Log](/fin7/CHANGE_LOG.md)