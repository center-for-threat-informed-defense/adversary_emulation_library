 # ---------------------------------------------------------------------------
 # snake_cleanup.ps1 - Cleans up Snake and its lateral movement artifacts. To be executed from a domain controller with administrative privileges.

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: .\snake_cleanup.ps1 -targets TARGET [-restart] [-deleteInstaller]
 #    Ex: .\snake_cleanup.ps1 -targets azuolas,berzas,uosis -restart -deleteInstaller
 #    Ex: .\snake_cleanup.ps1 -targets azuolas
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

param($targets, [switch]$restart, [switch]$deleteInstaller)

$ErrorActionPreference="Continue"

function Cleanup-Service {
    param (
        $target,
        $serviceName,
        $debugMsgName
    )

    if (Get-Service -ComputerName $target -Name "$serviceName" -ErrorAction Ignore) {
        sc.exe \\$target stop "$serviceName" | Out-Null
        if ( (Get-Service -ComputerName $target -Name "$serviceName").Status -ne "Stopped") {
            Write-Host -ForegroundColor Red "  [!] $serviceName was not stopped"
        } else {
            echo "  [+] Stopped $debugMsgName service $serviceName"
        }
	    sc.exe \\$target delete "$serviceName" | Out-Null
        if (Get-Service -ComputerName $target -Name "$serviceName" -ErrorAction Ignore) {
            Write-Host -ForegroundColor Red "  [!] $serviceName was not deleted"
        } else {
            echo "  [+] Removed $debugMsgName service $serviceName"
        }
    } else {
        echo "  [-] Service $serviceName ($debugMsgName) not found. Skipping."
    }

}

function Remove-CheckFile {
    param (
        $path,
        $debugMsgName
    )

    if (Test-Path $path) {
        Remove-Item -Recurse -Force $path
        if (Test-Path $path) {
            Write-Host -ForegroundColor Red "  [!] $debugMsgName was not deleted"
        } else {
            echo "  [+] Removed $debugMsgName at $path"
        }
    } else {
        echo "  [-] $debugMsgName at $path not found. Skipping."
    }

}

foreach ($target in $targets) {
    Write-Host -ForegroundColor Yellow "[+] Performing initial Snake cleanup on $target"

    # Clean up PsExec artifacts
    echo "[+] Cleaning up PsExec artifacts"
    Cleanup-Service -target $target -serviceName "psexesvc" -debugMsgName "PsExec"
    $psexecBinaries = @("psexesvc.exe", "cmu_svc_v2.exe", "cmu_svc.exe")
    foreach ($bin in $psexecBinaries) {
        Invoke-Command -ComputerName $target -ScriptBlock ${Function:Remove-CheckFile} -ArgumentList "C:\Windows\$bin", "PsExec Binary"
    }

    # Clean up signed driver service
    echo "[+] Cleaning up signed driver service"
    Cleanup-Service -target $target -serviceName "gigabit" -debugMsgName "signed driver"

    # Clean up unsigned driver service
    echo "[+] Cleaning up unsigned driver service"
    Cleanup-Service -target $target -serviceName "gusb" -debugMsgName "unsigned driver"

    # Clean up installer directory
    echo "[+] Cleaning up installer directory"
    $installerDir = 'C:\Windows\$NtUninstallQ608317$';
    Invoke-Command -ComputerName $target -ScriptBlock ${Function:Remove-CheckFile} -ArgumentList $installerDir, "Installer Directory"

    # Delete Snake installer
    if ($deleteInstaller) {
        $installerExePaths = @("C:\Users\egle\Desktop\gusbsys.exe", "C:\Windows\system32\cmu_svc_v2.exe", "C:\Windows\System32\cmu_svc.exe")
        foreach ($path in $installerExePaths) {
            Invoke-Command -ComputerName $target -ScriptBlock ${Function:Remove-CheckFile} -ArgumentList $path, "Snake Installer"
        }

    } else {
        echo "[-] Not deleting Snake installer"
    }
}

# Restart computer
if ($restart) {
    Write-Host -ForegroundColor Yellow "[+] Restarting $($targets -join ", ") in 5 seconds...";
    Start-Sleep 5;
    echo "[+] Restarting $targets and waiting for PowerShell connectivity. This may take a few minutes..."
    Restart-Computer -ComputerName $targets -Wait -For PowerShell -Delay 10 -Force
    echo "[+] Restart of $($targets -join ", ") is complete";
} else {
    echo "[-] Not restarting $($targets -join ", ")";
}

foreach ($target in $targets) {
    Write-Host -ForegroundColor Yellow "[+] Performing final Snake cleanup on $target"

    # Clean up unsigned driver service
    echo "[+] Cleaning up unsigned driver service again"
    Cleanup-Service -target $target -serviceName "gusb" -debugMsgName "unsigned driver"

    # Remove dropped usermodule DLL
    echo "[+] Cleaning up user module DLL"
    $userModuleDLL = "C:\Windows\msnsvcx64.dll"
    Invoke-Command -ComputerName $target -ScriptBlock ${Function:Remove-CheckFile} -ArgumentList $userModuleDLL, "User Module DLL"
}

echo "[+] Snake clean up on $($targets -join ", ") completed" 
