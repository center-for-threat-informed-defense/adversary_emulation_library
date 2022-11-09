# Add RegKey Path as it does not exist on the DC
Write-Host "[i] Disabling Windows Defender"
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\" -Name "Windows Defender" -ErrorAction Continue
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft' -Name "Windows Defender" -Force -ErrorAction Continue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force -ErrorAction Continue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1 -PropertyType DWORD -Force -ErrorAction Continue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpyNetReporting" -Value 0 -PropertyType DWORD -Force -ErrorAction Continue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0 -PropertyType DWORD -Force -ErrorAction Continue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontReportInfectionInformation" -Value 1 -PropertyType DWORD -Force -ErrorAction Continue


# set preferences for Windows Defender scans and updates - may error out if Defender is already disabled
Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true `
-DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true `
-DisableArchiveScanning $true -DisableCatchupFullScan $true -DisableCatchupQuickScan $true `
-DisableEmailScanning $true -DisableRemovableDriveScanning $true -DisableScanningMappedNetworkDrivesForFullScan $true `
-DisableScanningNetworkFiles $true -SignatureDisableUpdateOnStartupWithoutEngine $true -DisableBlockAtFirstSeen $true `
-SevereThreatDefaultAction 6 -MAPSReporting 0 -HighThreatDefaultAction 6 -ModerateThreatDefaultAction 6 -LowThreatDefaultAction 6 `
-SubmitSamplesConsent 2 -ErrorAction Continue

# exclude C drive from A/V scans - may error out if Defender is already disabled
Add-MpPreference -ExclusionPath "C:\" -ErrorAction Continue

# modify defender to disable real-time protection
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name "Real-Time Protection" -Force -ErrorAction Continue
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -PropertyType DWORD -Force -ErrorAction Continue

# commented out code for later use -- passive mode for Windows Defender
#New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" 
#New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" -Name "ForceDefenderPassiveMode" -Value 1 -PropertyType DWORD
