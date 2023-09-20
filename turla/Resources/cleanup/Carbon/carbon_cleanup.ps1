# ---------------------------------------------------------------------------
# carbon_cleanup.ps1 - Uninstalls Carbon DLL malware and cleans up artifacts. Requires elevated permissions.

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: .\carbon_cleanup.ps1

# Revision History:

# --------------------------------------------------------------------------- 

$ErrorActionPreference="Stop";

$baseDir = "C:\Program Files\Windows NT"

# Clean up loader DLL service
$serviceName = "WinResSvc";
$svchostRegKey = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost";
$svchostRegValue = "WinSysRestoreGroup";
if (Get-Service -Name "$serviceName" -ErrorAction Ignore) {
	$svcProc = tasklist /svc /fi "SERVICES eq $serviceName" /fo csv | convertfrom-csv;
	if ($svcProc) {
		$targetPid = $svcProc.PID;
		echo "[+] Killing service process for $serviceName and PID $targetPid";
		Stop-Process -Force -Id $targetPid;
		echo "[+] Killed service process for $serviceName"; 
		Start-Sleep 5;
	}
	
    Stop-Service -Name "$serviceName" -Force -PassThru;
	echo "[+] Stopped loader DLL service $serviceName";
	sc.exe delete "$serviceName";
	echo "[+] Removed loader DLL service $serviceName";
} else {
    echo "[-] Loader DLL service $serviceName not found";
}

# Kill Edge processes
echo "[+] Killing Edge processes.";
Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force;
Start-Sleep 5;

if (Test-Path -Path "HKLM:\$svchostRegKey") {
    if (Get-ItemProperty -Path "HKLM:\$svchostRegKey" -Name "$svchostRegValue" -ErrorAction Ignore) {
        reg delete "HKLM\$svchostRegKey" /v "$svchostRegValue" /f;
		echo "[+] Removed loader DLL service svchost registry key value $svchostRegValue under path HKLM\$svchostRegKey";
    } else {
        echo "[-] Could not find value $svchostRegValue under registry key HKLM\$svchostRegKey";
    }
} else {
    echo "[-] Could not find svchost registry key HKLM\$svchostRegKey";
}

# Clean up subfolders
$nlsDir = "$baseDir\Nlts";
if (Test-Path "$nlsDir") {
	Remove-Item -Recurse -Force "$nlsDir";
	echo "[+] Removed Nls subdir $nlsDir";
} else {
	echo "[-] Nls subdir $nlsDir not found. Skipping."
}
$tasksDir = "$baseDir\0511";
if (Test-Path "$tasksDir") {
	Remove-Item -Recurse -Force "$tasksDir";
	echo "[+] Removed tasks subdir $tasksDir";
} else {
	echo "[-] Tasks subdir $tasksDir not found. Skipping."
}
$tasksOutputDir = "$baseDir\2028";
if (Test-Path "$tasksOutputDir") {
	Remove-Item -Recurse -Force "$tasksOutputDir";
	echo "[+] Removed task output subdir $tasksOutputDir";
} else {
	echo "[-] Task output subdir $tasksOutputDir not found. Skipping."
}

# Clean up Orchestrator log files
$orchResultLog = "$baseDir\history.jpg";
if (Test-Path "$orchResultLog") {
	rm -force "$orchResultLog";
	echo "[+] Removed orch result log file $orchResultLog";
} else {
	echo "[-] Orch result log file $orchResultLog not found. Skipping."
}

$orchErrorLog = "$baseDir\bootinfo.dat";
if (Test-Path "$orchErrorLog") {
	rm -force "$orchErrorLog";
	echo "[+] Removed orch error log file $orchErrorLog";
} else {
	echo "[-] Orch error log file $orchErrorLog not found. Skipping."
}

# Clean up dropped components
$configPath = "$baseDir\setuplst.xml"
if (Test-Path "$configPath") {
	rm -force "$configPath";
	echo "[+] Removed config file $configPath";
} else {
	echo "[-] Config file $configPath not found. Skipping."
}

$orchestratorDllPath = "$baseDir\MSSVCCFG.dll";
if (Test-Path "$orchestratorDllPath") {
	rm -force "$orchestratorDllPath";
	echo "[+] Removed orchestrator DLL $orchestratorDllPath";
} else {
	echo "[-] orchestrator DLL $orchestratorDllPath not found. Skipping."
}

$commsDllPath = "$baseDir\msxhlp.dll";
if (Test-Path "$commsDllPath") {
	rm -force "$commsDllPath";
	echo "[+] Removed communications library DLL $commsDllPath";
} else {
	echo "[-] communications library DLL $commsDllPath not found. Skipping."
}

$loaderDllPath = "C:\windows\System32\mressvc.dll";
if (Test-Path "$loaderDllPath") {
	rm -force "$loaderDllPath";
	echo "[+] Removed loader DLL $loaderDllPath";
} else {
	echo "[-] Loader DLL $loaderDllPath not found. Skipping."
}

# Delete dropper executable
$dropperPaths = "C:\Windows\System32\WinResSvc.exe","C:\Windows\System32\wmimetricsq.exe","C:\Windows\wsqmanager.exe","C:\Windows\System32\wsqmanager.exe";
foreach ($dropperPath in $dropperPaths) {
	if (Test-Path "$dropperPath") {
		rm -force "$dropperPath";
		echo "[+] Removed Carbon installer at $dropperPath";
	}
}
