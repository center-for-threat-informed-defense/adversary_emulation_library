# Emulation Plan Structure

Each emulation plan is built based on the same structural components:

- **Scenario:** An end-to-end, emulated campaign typically spanning (pre-)compromise behaviors through the adversary achieving their operational objective(s)
- **Step:** A grouping of behaviors related to a specific adversary goal within a Scenario, typically aligns at the same level of abstraction as [ATT&CK Tactics](https://attack.mitre.org/tactics/)
- **Sub-Step / Procedure:** Each specific behavior to be executed during the emulation, typically aligns at the same level of abstraction as [ATT&CK Techniques](https://attack.mitre.org/techniques/)

The following notional operations flow diagram outlines this structure:

![](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/structural-documentation/notional_diagram.PNG)

## Additional Considerations

Each operations flow is designed based on what scenario(s) are being captured in the emulation from the cyber threat intelligence describing the target adversary's operational activity. Thusly, operational flows will be sequential but not always   linear.

![](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/structural-documentation/notional_diagram_loops.PNG)

In this case, there is a loop between the third and fifth Steps (*Maintain Access* through *Pivot to New Victim*) before reaching the last Step in the Scenario.

We have also defined an additional, optional component of a **Phase** to capture groupings of Steps that can be interchanged.

![](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/structural-documentation/notional_diagram_phases.PNG)

In this case, the second Phase has two alternative Step options (*Steal Data* or *Destroy Data*) and creates two distinct Scenarios.
