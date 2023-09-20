 # ---------------------------------------------------------------------------
 # epic_cleanup.ps1 - Cleans up EPIC binaries, persistence, and privilege escalation artifacts. To be executed from a domain controller with administrative privileges.

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: .\epic_cleanup.ps1 -target TARGET -user USERNAME [-restart]
 #    Ex: .\epic_cleanup.ps1 -target hobgoblin -user gunter -restart
 #    Ex: .\epic_cleanup.ps1 -target azuolas -user egle
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

param($target, $user, [switch]$restart)

$ErrorActionPreference="Continue"

Write-Host "Cleaning up EPIC on $target"

# Clean up signed driver service
$serviceName = "ViperVPNSvc"
if (Get-Service -ComputerName $target -Name "$serviceName" -ErrorAction Ignore) {
    sc.exe \\$target stop $serviceName
    echo "[+] Stopped vulnerable service $serviceName"
    Invoke-Command -ComputerName $target -ScriptBlock { reg add "HKLM\system\currentcontrolset\services\ViperVPNSvc" /t REG_EXPAND_SZ /v ImagePath /d "C:\terraform\viperVpn.exe" /F }
    echo "[+] Restored vulnerable service $serviceName"
} else {
    Write-Host -ForegroundColor Yellow "[!] Vulnerable service $serviceName not found"
}

# Kill Edge processes
echo "[+] Killing Edge processes.";
Invoke-Command -ComputerName $target -ScriptBlock { Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force };
Start-Sleep 5;

Invoke-Command -ComputerName $target -ScriptBlock {
    # Cleanup winlogon registry persistence
    $userSID = (Get-ChildItem -Path: "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Get-ItemProperty | Where-Object -Property ProfileImagePath -Value "C:\Users\$Using:user" -EQ ).PSChildName;
    if ($userSID -eq $null) {
        Write-Host -ForegroundColor Red "[!] SID for $Using:user not found. Do not include domain in username."
    }
    $winlogonPath = "registry::HKEY_USERS\$userSID\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    if (Test-Path $winlogonPath) {
        if ((Get-ItemProperty -path $winlogonPath).PSObject.Properties.Name -contains "Shell") {
            $winlogonKey = (Get-ItemPropertyValue -path $winlogonPath -Name Shell -ErrorAction Ignore);
            if ($winlogonKey.Contains("mxs_installer.exe")) {
                Remove-ItemProperty -path $winlogonPath -Name Shell;
                echo "[+] Removed Winlogon Shell registry key value";
            } else {
                echo "[-] Winlogon Shell registry key value not found. Skipping.";
            }
        } else {
            echo "[-] Winlogon Shell registry key value not found. Skipping.";
        }
    } else {
        Write-Host -ForegroundColor Yellow "[!] Winlogon path '$winlogonPath' not found"
    }


    # Cleanup EPIC injector
    $injectorExe = "C:\users\$Using:user\AppData\Local\Temp\mxs_installer.exe"
    if (Test-Path $injectorExe) {
        Remove-Item -Force "$injectorExe"
        echo "[+] Removed installer executable"
    } else {
        echo "[-] Installer executable $injectorExe not found. Skipping."
    }

    # Cleanup EPIC log file
    $logFile = "C:\users\$Using:user\AppData\Local\Temp\~D723574.tmp";
    if (Test-Path "$logFile") {
	    Remove-Item -Force "$logFile";
	    echo "[+] Removed logging file $logFile"
    } else {
	    echo "[-] Logging file $logFile not found. Skipping.";
    }

    # Cleanup EPIC dropper
    $dropperPaths = "C:\users\$Using:user\Downloads\NTFVersion.exe","C:\users\$Using:user\Downloads\NFVersion_5e.exe";
    foreach ($dropperPath in $dropperPaths) {
        if (Test-Path "$dropperPath") {
            Remove-Item -Force $dropperPath;
	    echo "[+] Removed EPIC dropper at $dropperPath";
	}
    }
}

# Restart computer
if ($restart) {
    echo "[+] Restarting $target in 5 seconds...";
    Start-Sleep 5;
    Restart-Computer -ComputerName $target -Force;
} else {
    echo "[-] Not restarting $target";
}

echo "[+] EPIC clean up on $target completed";
