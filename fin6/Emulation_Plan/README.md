# FIN6 Emulation Plan

This folder contains the core components of the FIN6 emulation plan. Each component is summarized below, and explained in detail in the announcement blog post: [TODO: Link to blog post]

The Operations Flow chains techniques together into a logical flow of the major Steps that commonly occur across FIN6 operations. In the case of FIN6, we describe their Operations in two major Phases:

- Phase 1: The primary focus of this phase is initial access and placement within the target environment, and exfiltrating relevant data identified during this phase (eg credentials).
- Phase 2: This phase consists of the specific objectives or effects of the operation. We provide three potential options for specific objectives, based on historical FIN6 operations.

The FIN6 emulation plan is a human-readable, step-by-step / command-by-command implementation of FIN6 TTPs. Structurally, the plan is organized into 2 phases, as defined in the Operations Flow. The human-readable plan is accompanied by a machine-readable plan implemented in YAML. The YAML includes all steps, commands, and syntax for both Phase 1 and Phase 2. The YAML template was nuanced to ensure that each step within the YAML is directly coupled with its equivalent in the human-readable version.

## Table of Contents

- [Intelligence Summary](/fin6/Intelligence_Summary.md)
- [Operations Flow](/fin6/Operations_Flow.md)
- [Emulation Plan](/fin6/Emulation_Plan/README.md)
  - [Phase 1](/fin6/Emulation_Plan/Phase1.md)
  - [Phase 2](/fin6/Emulation_Plan/Phase2.md)
  - [YAML](/fin6/Emulation_Plan/FIN6.yaml)