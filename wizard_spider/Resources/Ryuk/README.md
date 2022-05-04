# Ryuk

A ransomware designed to target enterprise environments.

## Overview

The Ryuk ransomware in this scenario has the last step of causing impact on the enterprise network. Among its goals it will stop services, delete backups, mount any discoverable shares and ultimately encrypt the files of the infected machine. 

## Pre Requirements

In order to accurately execute this this project you will need to generate an RSA 2048 keypair. Use the following commands as an example with openssl to create them:

```
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
awk '{print"\""$0"\""}' < private.pem
awk '{print"\""$0"\""}' < public.pem
```

You will also need to create an AES256 key or use the WinAPI to generate it programmatically with [CryptGenKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenkey). Use the following command as an example with openssl to create it:

```
openssl enc -aes-256-cbc -k secret -pbkdf2 -iter 100000 -P -md sha256
```

Keep the keys in a secure location, otherwise recovering any files after the project runs will not be possible.

## Remarks

This project in particular has been defanged in preparation for public release. The encryption logic has been removed and needs to be implemented to provide the impact capability. Below is a source code changes checklist that needs to be satisfied before continuing with compilation and use of this resource:

- `ryuk/file_encryption.cc` needs the EncryptionProcedure function to be implement
- `ryuk/mount_share_operations.cc` MountShare function needs szUserName and szPassword initialized with compromised credentials
- `ryuk/mount_share_operations.cc` LoopAndAttemptDriveMountOnAddresses may need the IP address updated depending on your range deployment
- (Optional) if you wish to expand the scope of the encryption procedures or share discovery behavior you can look into the bEvalsMode variable and toggle its value (TRUE by default). You may also want to revise which drives you want to encrypt in case the letters don't match up.

## Usage

After understanding the remarks and pre-requirements and making the appropiate changes to the source code use following command to compile the binaries for this project:

```
cd wizard_spider\Resources\Ryuk\ryuk
"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe" ryuk.sln /build Release
```

If successful, it will generate two binaries: `ryuk.exe` is the main ransomware (careful do not run it accidentally on your host), `RyukTests.exe` contains the test suite for the project.

The `ryuk.exe` requires admin privileges on the machine to properly modify its SE_TOKENS, perform the injection, and encrypt the contents of the host.

## Ryuk Executable Options

```
Usage: ryuk.exe <option(s)>
Options:
    -h,--help               Show this help message
    -e,--encrypt            Confirm you want to encrypt this system
    -p,--process-name       The process name to search and perform process injection (case sensitive)
    --disconnect-shares     Disconnect shares, this is a separate option just in case you need to reset.
    --drop-bat-files        Drops kill.bat and window.bat into C:/Users/Public, it will perform the network share discovery.
```

## Output sample and File example

The image below shows the encrypted file details. Right at the end of the encrypted file the string "RYUKTM" (12 bytes) is present and followed by the encrypted AES256 key (268 bytes)

![HEX editor showing an encrypted file](img/encrypted_file_sample.PNG?raw=true "Encrypted file example")

This image shows the project running, and the typical output you might expect

![CMD showing tool execution](img/tool_execution.png?raw=true "Running tool output")

## Testing

To build and run tests for this binary execute the same command used for compiling the main binary found on the [Usage Section](#Usage) of this page. If this step has already been executed, you should see two binaries in the Release folder. The one named "RyukTests.exe" corresponds to the test suite.

## Fixes

The version of the ryuk source code found on this project has a patch applied to avoid a race condition bug where the main process would start cleaning up memory before waiting for the encryption threads to finish. This would leave some files or drives not encrypted, and would likely cause the injected process to crash as well. The exact details of the changes are under the diff `ryuk/synchronization_changes.patch`.

### References

- https://attack.mitre.org/software/S0446/
- https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/
- https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-006.pdf
- https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/
- https://thedfirreport.com/2020/10/08/ryuks-return/
- https://n1ght-w0lf.github.io/malware%20analysis/ryuk-ransomware/
