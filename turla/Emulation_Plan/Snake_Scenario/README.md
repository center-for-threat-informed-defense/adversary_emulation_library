# Snake Scenario

For ATT&CK Evaluations Enterprise Round 5, the Snake scenario was developed to
emulate Turla's utilization of the following software:
- Epic
- Snake
- PsExec
- Mimikatz
- LightNeuron

## [Detections Scenario](./Snake_Detections_Scenario.md)

This 9 step scenario was created for the Detections portion of ATT&CK
Evaluations Enterprise Round 5, where all prevention mechanisms and protection
tooling is **disabled** to allow the full emulation plan to execute unobstructed.
This allows the scenario to be executed from beginning to end, with each step
building upon the previous. and for telemetry on red team activity to be
gathered in full. 

## [Protections Scenario](./Snake_Protections_Scenario.md)

The scenario created for the Detections portion was modularized into 6 discrete
tests to create the Protections portion of ATT&CK Evaluations Enterprise Round
5, where prevention mechanisms and protection tooling is **enabled**. This
highlights protection capabilities of the deployed solution and encourages
blocks of red team activity as early as possible. For this reason, this
version of the scenario was designed to removes the dependencies between each
step.

## Infrastructure

This scenario was executed on the following infrastructure:

![Snake Infrastructure Diagram](../../Resources/Images/SnakeInfrastructure.png)

Reference [setup](../../Resources/setup/) for guidance on deploying the
infrastructure used by this scenario.