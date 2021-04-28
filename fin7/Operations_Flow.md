# FIN7 Operations Flow

Please see the formal [FIN7 Intelligence Summary](/fin7/Intelligence_Summary.md) which includes a break-down of the cited intelligence used for each step of this emulation.

---

<p align="center">
  <img src="/fin7/Emulation_Plan/OpFlow_Diagram.png" />
</p>

---

# Scenario 1

Based on [BOOSTWRITE](https://attack.mitre.org/software/S0415//), [Pillowmint](https://attack.mitre.org/software/S0517/), [SQLRat](https://attack.mitre.org/software/S0390/), and [BabyMetal](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html)

This scenario emulates FIN7 targeting a hotel manager network to gain access to credit card information. The scenario begins with FIN7 achieving initial access to the network after an unwitting user executes a malicious .LNK file. FIN7 then pivots to a privileged IT administrator workstation. From this system, FIN7 keylogs credentials needed to access an accounting workstation. FIN7 then pivots to the accounting workstation, establishes persistence, and deploys malware to scrape credit card information from process memory.

This emulation plan is intended to be executed with protections-based capabilities **disabled** in order to accurately measure a security control's ability to detect specific adversary behavior.

---

# Scenario 2
This scenario emulates the same FIN7 TTP's as scenario 1; however, changes were made to support environments with Protective security controls enabled. This scenario is designed so that specific TTP's are decoupled from dependencies to enable all steps to be executed, even if previous steps are blocked.

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
- [Issues](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/issues)
- [Change Log](/fin7/CHANGE_LOG.md)
