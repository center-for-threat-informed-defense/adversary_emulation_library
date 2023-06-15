# OSX.OceanLotus

| Components | Use | Description |
| ---------- | --- | ----------- |
| Application Bundle | First stage | Masquerades as a Word doc, executes script on click that drops and executes the Second Stage Implant |
| Implant | Second stage | Installs persistence and performs backdoor capabilities |

## Description

### Application Bundle (First Stage)
This component is an application bundle containing the following items:
- Bash script
- Decoy Word document 
- Microsoft Word icon

The bash script contains the base64 encoded Implant (Second Stage)
embedded within it. On application bundle open, the bash script is executed and
performs the following actions:
- Removes quarantine flag on files within the application bundle
- Extracts, base64 decodes, and executes the embedded Implant (Second
Stage) payload
- Uses `touch` to update the timestamps of the Implant (Second Stage)
- Replaces the application bundle with the decoy Word document

### Implant (Second Stage)
This component is a fat binary embedded within the bash script in the
Application Bundle (First Stage) that performs the backdoor capabilities. On
execution, the Implant (Second Stage) automatically performs the following
actions:
- Installs persistence via LaunchAgent
- Collects OS information
- Registers with C2 server

**C2 Communication**

**Available Instructions**
| Instruction | Action |
| ----------- | ------ |
| | |

**Obfuscation**

## For Operators

### Execution

### Troubleshooting

### Cleanup

## For Developers 

### Dependencies

### Building

### Testing
