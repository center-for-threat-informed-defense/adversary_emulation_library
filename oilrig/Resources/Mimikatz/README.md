# Mimikatz

Mimikatz was used to list all available provider credentials using `sekurlsa::logonPasswords` and perform Pass-The-Hash via `sekurlsa::pth`.

For this scenario, no significant changes were made to the original functionality of Mimikatz.

Source code and pre-built Mimikatz can be downloaded from: https://github.com/gentilkiwi/mimikatz/

### Dependencies

To build the binary with the following instructions, you will need the following dependencies downloaded and installed:

- [Microsoft Visual Studio](https://visualstudio.microsoft.com/downloads/)
- [Windows Driver Developer Kit (WinDDK)](http://www.microsoft.com/download/details.aspx?id=11800)

### Build Instructions

From the [mimikatz folder](/Resources/Mimikatz/mimikatz/), run the following command:

```
"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe" mimikatz.sln /build release
```

The resulting executable will be found in the x64 folder created during the build process.

This executable should be renamed as `m64.exe` and should be copied to Resources/payloads/TwoFace.

### :microscope: CTI Sources

- [Unit42's TwoFace Webshell: Persistent Access Point for Lateral Movement](https://unit42.paloaltonetworks.com/unit42-twoface-webshell-persistent-access-point-lateral-movement/)
- [Unit42's Striking Oil: A Closer Look at Adversary Infrastructure](https://unit42.paloaltonetworks.com/unit42-striking-oil-closer-look-adversary-infrastructure/)
- [Unit42's Oilrig Playbook Viewer](https://pan-unit42.github.io/playbook_viewer/?pb=oilrig)

### :microscope: ATT&CK Techniques

While [Mimikatz](https://attack.mitre.org/software/S0002/) covers a wider range of techniques, the version used in the scenario displayed the following:

- [(Step6)](../../Emulation_Plan/README.md#step-6---privileged-credential-dumping) [T1003.001](https://attack.mitre.org/techniques/T1003/001/) - OS Credential Dumping: LSASS Memory
- [(Step8)](../../Emulation_Plan/README.md#step-8---lateral-movement-to-the-sql-server) [T1550.002](https://attack.mitre.org/techniques/T1550/002/) - Use Alternate Authentication Material: Pass the Hash
