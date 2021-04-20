<#
.SYNOPSIS
    This script will generate RAM load to the specified memory.
    For best results run once in dedicated console per use.
.DESCRIPTION
    This script will generate RAM load to the specified memory value. 
    This will be the total RAM utilized by the system. 
    If other progams are running they will be counted towards the specified load. 
    TargetRAM can only be higher than currently utilized memory. 
    To revert RAM usage close console window or kill PowerShell process.
    All calculations are done in GB. 
.EXAMPLE
    .\RAMStressTest.ps1 -TargetRAM 4GB
.PARAMETER TargetRAM
    Amount of memory to be utilized. Note the denomination (MB, GB) - bytes are default.
.INPUTS

.NOTES
#>

[cmdletbinding(
    SupportsShouldProcess = $True,
    ConfirmImpact = 'High',
    PositionalBinding = "TargetRAM"
)]

param(
    [parameter(
        mandatory = $true,
        Position = 0
    )]
    [double]$TargetRAM
)

if ($TargetRAM -ge 1MB) {
    $TargetRAM /= 1GB
} else {
    Write-Error -Category InvalidArgument "RAM specified smaller than 1MB"
    return
}

#Get TotalPhysicalMemory
$TotalRAM = (Get-WmiObject -Class "Win32_ComputerSystem").TotalPhysicalMemory / 1GB

if ($TargetRAM -gt $TotalRAM) {
    $TargetRAM = $TotalRAM
}

#Get FreePhysicalMemory - Oddly returns incorrect multiple of 10, but correct size if adjusted
$FreeRAM = (Get-WmiObject -class "Win32_OperatingSystem").FreePhysicalMemory * 1KB / 1GB

$toAllocate = ( $TargetRAM - ($TotalRAM - $FreeRAM) )

Write-Host "Total Physical Memory:     $TotalRAM GB"
Write-Host "Free Physical Memory:      $FreeRAM GB"
Write-Host "Currently Utilized Memory: $([math]::round($TotalRAM - $FreeRAM, 14)) GB"
Write-Host "Memory To Be Allocated:    $([math]::round($toAllocate, 14)) GB"

if ($toAllocate -lt 0) {
    Write-Error -Category InvalidArgument "RAM is already above target"
    return
} 

Write-Warning "RAMStressTest will be tied to this PowerShell instance.
To return RAM usage to normal you will need to kill this console window/process"

if ($PSCmdlet.ShouldProcess("$toAllocate GB")) {
    Write-Host "Allocation Starting!"

    $chars = @("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
    $allocate = @()

    # Allocating in unique-ish chunks to avoid Windows memory compression
    for ($i = 0; $i -lt $chars.length; $i++) {
        $allocate += $chars[$i] * [math]::floor( ( ( $toAllocate * .5GB ) / $chars.length) )
    }
}

return
