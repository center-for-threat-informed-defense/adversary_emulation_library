# Micro Emulation Plan: File Access and File Modification

This micro emulation plan targets the [DS0022 File: File
Access](https://attack.mitre.org/datasources/DS0022/#File%20Access) and [DS0022
File: File
Modification](https://attack.mitre.org/datasources/DS0022/#File%20Modification)
data sources. It covers file interactions like reading a file and modifying a
file’s contents, permissions, or attributes. Ransomware attacks typically show a
combination of file access and modification conducted at a rapid pace. This
behavior is not unique to ransomware as it is very common for adversaries to
conduct file access or modification behaviors during various stages of an
attack, but the cadence between the two will be much slower than with
ransomware.

You can access the binary for this micro plan as part of the [latest release](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/releases). 

**Table Of Contents:**

- [Micro Emulation Plan: File Access and File Modification](#micro-emulation-plan-file-access-and-file-modification)
  - [Description of Emulated Behaviors](#description-of-emulated-behaviors)
  - [Cyber Threat Intel / Background](#cyber-threat-intel--background)
  - [Execution Instructions / Resources](#execution-instructions--resources)
    - [Execution Demo](#execution-demo)
  - [Defensive Lessons Learned](#defensive-lessons-learned)
    - [Detection](#detection)
    - [Mitigation](#mitigation)

## Description of Emulated Behaviors

**What are we doing?** This module provides easy to execute code that will
access and modify files in a directory supplied by the user or current directory
if none is specified. The executable will append a new line to `*.txt` files and
add a `.bk` extension to non-text files. It logs all of its filesystem activity
for auditing and cleanup purposes.

## Cyber Threat Intel / Background

**Why should you care?** File access and modification behavior can be found
during ransomware attacks ([T1486 Data Encrypted for
Impact](https://attack.mitre.org/techniques/T1486)) where the malware will open
files before encrypting them. This behavior of accessing a file and then
modifying it will be conducted in rapid succession giving little time for
defenders to recognize an attack and stop it. Some malware encrypting just the
first portion of the file to increase the speed at which it operates.

Adversaries may access or modify files for many different reasons including but
not limited to [T1087 Account
Discovery](https://attack.mitre.org/techniques/T1087) to enable system
enumeration, [T1005 Data from Local
System](https://attack.mitre.org/techniques/T1005) to conduct system and network
enumeration or find data for exfiltration, [T1555 Credentials from Password
Stores](https://attack.mitre.org/techniques/T1555) to facilitate lateral
movement or privilege escalation, and [T1074 Data
Staged](https://attack.mitre.org/techniques/T1074) as a precursor to
exfiltration.

## Execution Instructions / Resources

The `FileAccess.exe` executable executes by opening `*.txt` files and appending
a new line to each one. For non-text files it will add `.bk` to the filename. If
no directory is specified it will access and modify files in the directory it is
executed from (except itself, of course).

The executable has 4 options to alter its functionality:

1. `recur:` Conduct a recursive search on all directories that are found in the
   given path.
2. `dirPath:` The directory path to search for files to modify.
3. `logFile:` Allows the user to modify the name of the log file provided by
   the program.
4. `accessDelay:` Allows the user to specify an amount of time to wait between
   file access events.

Alternatively, the `-menu` argument displays an interactive menu to configure
the options.

### Execution Demo

![Animated screen capture demonstrating use of the tool.](docs/files.gif)

## Defensive Lessons Learned

### Detection

Windows generates [event ID
4663](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
when a file is accessed. With the nature of Ransomware being to encrypt as many
files as quickly as possible, a high volume of these alerts is a tell-tale sign
of ransomware activity. Non-ransomware file access behavior may be more
difficult to detect due the slower cadence.

Windows EID as well as Sysmon can be used to detect file modification behaviors
with Windows [event ID
4670](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670)
being used to detect when permissions to a file have been changed and Sysmon
[event ID
2](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-11-filecreate)
when a file’s creation time has changed. Sysmon [EID
11](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-11-filecreate)
monitors for when files are created. Many variants of ransomware delete the
original file and replace it with an encrypted copy posing a possible detection
opportunity.

### Mitigation

Accessing files and modifying them is extremely common behavior in all systems.
This coupled with the short time to respond makes mitigation very difficult and
revolves round preventing the ransomware from being deployed on the system in
the first place. Conducting regular backups and having “golden images” for
critical systems can limit the damage of a ransomware attack. Being able to
capture and log process memory is also important as the encryption key is often
stored in memory before being transferred to the adversary’s C2 server.
