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
- LaunchAgent plist file (PkgInfo)

The bash script contains the base64 encoded Implant (Second Stage)
embedded within it. On application bundle open, the bash script is executed and
performs the following actions:
- Removes quarantine flag on files within the application bundle
- Extracts, base64 decodes, and executes the embedded Implant (Second
Stage) payload
- Installs persistence via LaunchAgent
- Uses `touch` to update the timestamps of the Implant (Second Stage) artifacts
- Uses `chmod` to make the Implant (Second Stage) binary file executable by
changing file permissions to 755
- Replaces the application bundle with the decoy Word document

### Implant (Second Stage)
This component is a fat binary embedded within the bash script in the
Application Bundle (First Stage) that performs the backdoor capabilities. On
execution, the Implant (Second Stage) automatically performs the following
actions:
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

After executing the application bundle, execute the cleanup script and provide
the path to the folder where the application bundle was executed:

> NOTE: Do not include the trailing slash in the target path

```
./cleanup_osx.oceanlotus.sh $HOME/Documents
```

## For Developers 

### Dependencies

### Building

**Application Bundle**

To build the application bundle, run the following script from the
`ApplicationBundle` directory:

```
./build_bundle.sh -s first_stage.sh -i icon.icns -d decoy.doc -n "TestApp"
```

### Testing

## CTI Reporting
1. https://www.trendmicro.com/en_us/research/20/k/new-macos-backdoor-connected-to-oceanlotus-surfaces.html
1. https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/
1. https://www.trendmicro.com/en_us/research/18/d/new-macos-backdoor-linked-to-oceanlotus-found.html
1. https://www.welivesecurity.com/2019/04/09/oceanlotus-macos-malware-update/

## Resources
- appify - https://gist.github.com/oubiwann/453744744da1141ccc542ff75b47e0cf
- https://otx.alienvault.com/indicator/file/be43be21355fb5cc086da7cee667d6e7
- https://www.virustotal.com/gui/file/48e3609f543ea4a8de0c9375fa665ceb6d2dfc0085ee90fa22ffaced0c770c4f/detection