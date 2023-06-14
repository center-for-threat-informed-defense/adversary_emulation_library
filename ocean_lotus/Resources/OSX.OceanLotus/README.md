# OSX.OceanLotus

| Components | Use | Description |
| ---------- | --- | ----------- |
| Application Bundle | First stage | Masquerades as a Word doc, executes script on click that drops and executes the second stage Implant Dropper |
| Implant Dropper | Second stage | Embedded in the first stage script, installs persistence and drops the third stage Implant |
| Implant | Third stage | Performs backdoor capabilities |

## Description

### Application Bundle (First Stage)
This component is an application bundle containing the following items:
- Bash script
- Decoy Word document 
- Microsoft Word icon

The bash script contains the base64 encoded Implant Dropper (Second Stage)
embedded within it. On application bundle open, the bash script is executed and
performs the following actions:
- Removes quarantine flag on files within the application bundle
- Extracts, base64 decodes, and executes the embedded Implant Dropper (Second
Stage) payload
- Replaces the application bundle with the decoy Word document

### Implant Dropper (Second Stage)
This component is a fat binary embedded within the bash script in the
Application Bundle (First Stage). On execution, the Implant Dropper (Second
Stage) performs the following actions:
- Extracts the embedded Implant (Third Stage) to disk
- Installs persistence via LaunchAgent to execute the Implant (Third Stage)
- Uses `touch` to update the timestamps of the Implant (Third Stage)
- Deletes itself on completion

### Implant (Third Stage)
This component is a fat binary performing the implant backdoor capabilities.

**Capabilities**
| Instruction | Action |
| ----------- | ------ |
| | |

**C2 Communication**

**Obfuscation**

## For Operators

### Execution

### Troubleshooting

### Cleanup

## For Developers 

### Dependencies

### Building

### Testing
