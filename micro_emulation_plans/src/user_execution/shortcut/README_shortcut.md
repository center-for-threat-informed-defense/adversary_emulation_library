# README for User Execution of Shortcut

## Prerequisites

* OS: Windows 10
* Applications:
  * Web Browser - not necessary, but having one of the following installed will
    make the shortcut more realistic:
    Internet Explorer, Microsoft Edge, Google Chrome, Firefox
* Permissions:
  * You must be able to launch an instance of Powershell.
  * You must be able to write a file to your desktop.

## Executing the Application

* The tool distribution contains a `build/` directory containing the file
  `generate_lnk.exe`.
* Double-click the .exe to generate and open a shortcut with the default options:
  ```
  Command to execute: Resolve-DnsName -Name www.google.com -Server 1.1.1.1 | Out-File -FilePath .\\DnsName.txt
  ```
* For help with command line arguments, run `generate_lnk.exe -h`

The following payloads can be selected with the `-c/-command` argument or from
the interactive menu:

0. Resolve-DnsName -Name www.google.com -Server 1.1.1.1 | Out-File -FilePath .\\DnsName.txt
1. Get-NetIPAddress | Out-File -FilePath .\\NetIPAddress.txt
2. whoami /groups | Out-File -FilePath .\\whoami.txt
3. Get-Process | Out-File -FilePath .\\Process.txt
4. calc.exe
5. Supply your own PowerShell command.
