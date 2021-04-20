# Carbanak Operations Flow

Please see the formal [Carbanak Intelligence Summary](/Intelligence_Summary.md) which includes a break-down of the cited intelligence used for each step of this emulation.

---

<p align="center">
  <img src="/Emulation_Plan/CARBANAKopflow.png" />
</p>

---

# Scenario 1

Based on [Carbanak Malware](https://attack.mitre.org/software/S0030/), [Ggldr](https://www.forcepoint.com/blog/x-labs/carbanak-group-uses-google-malware-command-and-control), and [Mimikatz](https://attack.mitre.org/software/S0002/)

This scenario begins with a legitimate user executing a malicious payload delivered via spearphishing attacks targeting financial institutions. Following initial compromise, Carbanak expands access to other hosts through privilege escalation, credential accesss, and lateral movement with the goal of compromising money processing services, automated teller machines, and financial accounts. As Carbanak compromises potentially valuable targets, they establish persistence so that they can learn the financial organization's internal procedures and technology. Using this information, Carbanak transfers funds to bank accounts under their control, completing their mission.

This emulation plan is intended to be executed with protections-based capabilities **disabled** in order to accurately measure a security control's ability to detect specific adversary behavior.

---

# Scenario 2

This scenario emulates the same Carbanak TTP's as scenario 1; however, changes were made to support environments with protective security controls enabled. This scenario is designed so that specific TTP's are decoupled from dependencies to enable all steps to be executed, even if previous steps are blocked.



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
