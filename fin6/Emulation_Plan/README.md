# FIN6 Emulation Plan

This folder contains the core components of the FIN6 emulation plan. Each component is summarized below, and explained in detail in the announcement blog post: [TODO: Link to blog post]

The Operations Flow chains techniques together into a logical flow of the major Steps that commonly occur across FIN6 operations. In the case of FIN6, we describe their Operations in two major Phases:
- Phase 1: The primary focus of this phase is initial access and placement within the target environment, and exfiltrating relevant data identified during this phase (eg credentials).
- Phase 2: This phase consists of the specific objectives or effects of the operation. We provide three potential options for specific objectives, based on historical FIN6 operations.

The main FIN6 Emulation Plan is a human-readable, step-by-step / command-by-command implementation of FIN6 TTPs. For this specific Emulation Plan, the human-readable portion is broken into two halves, Phase 1 and Phase 2, mirroring the Operations Flow. 

The human-readable plan is accompanied by a machine-readable plan implemented in YAML. The YAML includes all steps, commands, and syntax for both Phase 1 and Phase 2. The YAML template was nuanced to ensure that each step within the YAML is directly coupled with its equivalent in the human-readable version.


## Table of Contents

* [YAML](FIN6.yaml)
* [OpFlow Diagram](OpFlow_Diagram.png)
* [Phase 1](Phase1.md)
* [Phase 2](Phase2.md)
