 <#
# ---------------------------------------------------------------------------
# range_validation.ps1 - Validate range configuration

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in 
# compliance with the License. You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed under the License 
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express 
# or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: range_validation.ps1
# --------------------------------------------------------------------------- 

Range Validation Script

  General script to validate the Vendor range as much as possible to ensure preflight checks will succeed.

  Should be executed from the Domain Controller of the range with Domain Admin privileges.

  How to run:

    .\range-validation.ps1

#>

$failed = $false

# DC computer names
$DC1 = 'bannik'
$DC2 = 'berlios'

# URL / IP Address for DNS check
$dnsMapping = @{ "wombatbattles.org" = "91.52.201.222" }

# Host mapping
if ($(hostname) -eq $DC1) {
  $rangeHosts = @{
    "bannik" = @{
        "hotfix" = "KB5013641","KB5015896","KB5017315";
        "os" = "Windows Server 2019 Datacenter";
        "build" = 17763;
    };
    "brieftragerin" = @{
        "hotfix" = "KB4483452","KB4486153","KB4493509","KB4493510";
        "os" = "Windows Server 2019 Datacenter";
        "build" = 17763;
        "no_mimikatz" = $true;
    };
    "hobgoblin" = @{
        "hotfix" = "KB5003791","KB5014032","KB5016705","KB5017022","KB5017308";
        "os" = "Windows 10 Pro";
        "build" = 19044;
    };
    "domovoy" = @{
        "hotfix" = "KB5003791","KB5014032","KB5016705","KB5017022","KB5017308";
        "os" = "Windows 10 Pro";
        "build" = 19044;
    };
    "khabibulin" = @{
        "hotfix" = "KB5003791","KB5014032","KB5016705","KB5017022","KB5017308";
        "os" = "Windows 10 Pro";
        "build" = 19044;
    };
    "kagarov" = @{
        "os" = "pc-linux-gnu";
    }
  }
} elseif ($(hostname) -eq $DC2) {
  $rangeHosts = @{
    "berlios" = @{
        "hotfix" = "KB5013641","KB5015896","KB5017315";
        "os" = "Windows Server 2019 Datacenter";
        "build" = 17763;
    };
    "berzas" = @{
        "hotfix" = "KB5013641","KB5015896","KB5017315";
        "os" = "Windows Server 2019 Datacenter";
        "build" = 17763;
    };
    "drebule" = @{
        "hotfix" = "KB4486153","KB5013641","KB5015896","KB5017315";
        "os" = "Windows Server 2019 Datacenter";
        "build" = 17763;
    };
    "uosis" = @{
        "hotfix" = "KB4578974","KB4580325","KB4586863","KB4592449";
        "os" = "Windows 10 Pro";
        "build" = 18362;
    };
    "azuolas" = @{
        "hotfix" = "KB4578974","KB4580325","KB4586863","KB4592449";
        "os" = "Windows 10 Pro";
        "build" = 18362;
    };
  };
}

# CPU check settings
$numCPUChecks = 3
$delayCPUCheckSeconds = 60

# List of Windows hostnames
$windowsHosts = $($rangeHosts.GetEnumerator().Name | where { $rangeHosts[$_]["os"].Contains("Windows") });


# Check execution on DC
if ($(hostname) -ne $DC1 -and $(hostname) -ne $DC2) {
  Write-Host -ForegroundColor red "[!] Script must be run from the domain controller of the range"
  exit
}

#
# Set all domain user password never expires to true
Write-Host "[+] Setting passwords to never expire";
Get-AdUser -Filter * | Set-ADUser -PasswordNeverExpires $true;
$passwordResult = Get-AdUser -Filter * -properties passwordlastset, passwordneverexpires
$passwordResult | ?{ $_.passwordneverexpires -ne $true } | %{ Write-Host -ForegroundColor red "  [!] Failed to set password to never expire for $($_.Name)"; $failed = $true; }

#
# Enable file and printer sharing for all Windows hosts
#
Write-Host "[+] Enabling File and Printer sharing for all Windows hosts"
Invoke-Command -ComputerName $windowsHosts -ScriptBlock {
  Enable-NetAdapterBinding -Name * -DisplayName "File and Printer Sharing for Microsoft Networks"
}

#
# Check operating system version
Write-host "[+] Validating domain computer operating systems";
$output = Get-AdComputer -Filter * -Properties Name, OperatingSystem| select name, operatingsystem;
$output | % {
    $operatingsystem = $_.operatingsystem;
    $computerName = $_.name;
    if ($operatingsystem -ne $rangeHosts[$computerName]["os"]) {
        Write-Host -ForegroundColor red "[!] Wrong major version for $($computerName). Expected $($rangeHosts[$computerName]["os"]), got $($operatingsystem)";
        $failed = $true;
    }
}

#
# Check build version for all Windows hosts
#
Write-Host "[+] Validating Windows host versions"
$output = Invoke-Command -ComputerName $windowsHosts -ScriptBlock {[System.Environment]::OSVersion.Version};
$output | % {
    if ($_.Major -ne 10) { Write-Host -ForegroundColor red "[!] Wrong major version for $($_.PSComputerName). Expected 10, got $($_.Major)" }
    if ($_.Minor -ne 0) { Write-Host -ForegroundColor red "[!] Wrong minor version for $($_.PSComputerName). Expected 0, got $($_.Minor)" }
    if ($_.Revision -ne 0) { Write-Host -ForegroundColor red "[!] Wrong revision for $($_.PSComputerName). Expected 0, got $($_.Revision)" }
    $build = $_.Build;
    $computerName = $_.PSComputerName;
    if ($build -ne $rangeHosts[$computerName]["build"]) {
        Write-Host -ForegroundColor red "[!] Wrong major version for $($computerName). Expected $($rangeHosts[$computerName]["build"]), got $($build)";
        $failed = $true;
    } else {
        Write-Host "    [+] Verified build version $($build) for $($computerName)"
    }
}

#
# Check hotfixes for all Windows hosts
#
foreach ($targhost in $windowsHosts) {
  Write-Host "[+] Validating hotfixes for $($targhost)"
  $actual = Invoke-Command -ComputerName $targhost -ScriptBlock { Get-HotFix | %{ $_.HotfixID} };
  $expected = $rangeHosts[$targhost]["hotfix"];
  $missing = $expected | ?{$actual -notcontains $_};
  $extra = $actual | ?{$expected -notcontains $_};
  if ($missing.Count -gt 0) {
    $missing | %{ Write-Host -ForegroundColor red "  [!] Error: $targhost missing hotfix $_" };
    $failed = $true;
  }
  if ($extra.Count -gt 0) {
    $extra | %{ Write-Host -ForegroundColor red "  [!] Error: $targhost has extra hotfix $_" };
    $failed = $true;
  }
}

#
# DNS check for all Windows hosts
#
foreach ($targhost in $windowsHosts) {
  Invoke-Command -ComputerName $targhost -ArgumentList $dnsMapping -ScriptBlock {
    Write-Host "[+] Validating DNS for $(hostname)"
    Clear-DnsClientCache

    $recordMapping = $args[0]

    foreach ($domain in $recordMapping.Keys) {
      $ipaddr = (Resolve-DnsName -DnsOnly -Type A -Name $domain).IpAddress
      if (-Not $ipaddr) {
        Write-Host -ForegroundColor red "  [!] Error: No IPv4 address found for ${domain}"
        $failed = $true
      } elseif ($ipaddr -ne $recordMapping.$domain) {
        Write-Host -ForegroundColor red "  [!] Error: Wrong IPv4 address for ${domain}. Expected $($recordMapping.$domain), got ${ipaddr}"
        $failed = $true
      }
    }
    Clear-DnsClientCache
  }
}

#
# Check CPU Utilization on Windows hosts
#
Write-Host "[+] Checking CPU Utilization on Windows hosts $numCPUChecks times and sleeping $delayCPUCheckSeconds seconds in between."
for ($i=0; $i -lt $numCPUChecks; $i++) {
    $job = Invoke-Command -ComputerName $windowsHosts -ScriptBlock {Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select Average} -AsJob
    Receive-Job -Job $job -Wait | Format-Table -Property Average,PSComputerName

    # only sleep if between checks
    if ($i -ne $numCPUChecks - 1) {
        Start-Sleep -Seconds $delayCPUCheckSeconds
    }
}

#
# Download Mimikatz
#
Write-Host "[+] Downloading Mimikatz to $(hostname)"
Invoke-Command -ComputerName $windowsHosts -ScriptBlock {

    $source = "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip"
    $zip = "C:\Users\Public\mimikatz_trunk.zip"
    $dest = "C:\Users\Public\mimikatz"

    Invoke-WebRequest -URI $source -OutFile $zip;
    Expand-Archive -Path $zip -DestinationPath $dest -Force
}

#
# Run and then delete mimikatz.exe
#
Write-Host "  [+] Running Mimikatz LSA dump on $(hostname)"
Start-Sleep -Seconds 3;
$output = $(Invoke-Command -ComputerName $(hostname) -ScriptBlock {C:\Users\Public\mimikatz\x64\mimikatz.exe "lsadump::lsa /inject" exit})
if ($output.Length -lt 20) {
    $failed = $true
    Write-Host -ForegroundColor red "    [!] Mimikatz LSA dump on $(hostname) failed:"
    $output
}

foreach ($targhost in $windowsHosts) {
  if ($rangeHosts[$targhost]["no_mimikatz"]) {
    continue
  }
  Write-Host "  [+] Running Mimikatz LogonPasswords on $targhost"
  Start-Sleep -Seconds 3;
  $output = $(Invoke-Command -ComputerName $targhost -ScriptBlock {C:\Users\Public\mimikatz\x64\mimikatz.exe sekurlsa::logonpasswords exit})
  if ($output.Length -lt 20) {
    $failed = $true
    Write-Host -ForegroundColor red "    [!] Mimikatz LSA dump on $targhost failed:"
    $output
  }
}
Invoke-Command -ComputerName $windowsHosts -ScriptBlock {Remove-Item -Path "C:\Users\Public\mimikatz*" -Force -Recurse};

#
# Log users off range hosts except evals_domain_admin on DC
#
Write-Host "[+] Logging off users on Windows hosts";
foreach ($targhost in $windowsHosts) {
    $job = Invoke-Command -ComputerName $targhost -ScriptBlock { query session } -AsJob
    Wait-Job $job | Out-Null
    if ($job.State -eq "Failed") {
        $failed = $true
        Write-Host -ForegroundColor red "  [!] Failed to get sessions for $targhost with error:"
        Receive-Job $job
        continue
    } else {
        $sessions = ($job | Receive-Job) -replace '\s{2,}', ',' | ConvertFrom-Csv | where { ($_.USERNAME -match "[a-z]") -and ($_.USERNAME -ne "") }

        $sessions | ForEach-Object {
            if ($targhost -eq $(hostname) -and $_.USERNAME -eq "evals_domain_admin") {
                Write-Host "  [+] Ignoring evals_domain_admin on $targhost"
                continue
            }
            Write-Host -ForegroundColor green "  [+] Logging off $($_.USERNAME) with session ID $($_.ID)";
            logoff $_.ID /server:$targhost;
        }
        if ($sessions.Length -EQ 0) {
            Write-Host "  [+] No users logged in to $targhost";
        }
    }
}

#
# Print message if any of the tests failed
if ($failed) {
  Write-Host -BackgroundColor white -ForegroundColor red "[!] Vendor range validation failed."
}
