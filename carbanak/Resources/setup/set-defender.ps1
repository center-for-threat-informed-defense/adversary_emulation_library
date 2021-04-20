# Prevent Defender from turning back on after reboot

# Add RegKey Path as it does not exist on the DC
New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\" -Name "Windows Defender" -ErrorAction Ignore
Set-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1

Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true `
-DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableScriptScanning $true `
-DisableArchiveScanning $true -DisableCatchupFullScan $true -DisableCatchupQuickScan $true `
-DisableEmailScanning $true -DisableRemovableDriveScanning $true -DisableScanningMappedNetworkDrivesForFullScan $true `
-DisableScanningNetworkFiles $true -SignatureDisableUpdateOnStartupWithoutEngine $true -DisableBlockAtFirstSeen $true `
-SevereThreatDefaultAction 6 -MAPSReporting 0 -HighThreatDefaultAction 6 -ModerateThreatDefaultAction 6 -LowThreatDefaultAction 6 `
-SubmitSamplesConsent 2 -ErrorAction Stop