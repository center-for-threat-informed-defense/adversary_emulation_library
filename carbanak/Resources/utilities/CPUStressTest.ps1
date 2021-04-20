<#
.SYNOPSIS
    This script will generate CPU load to the specified CPU percentage.
.DESCRIPTION
    This script will generate CPU load to the specified CPU percentage.
    Taking core count into consideration will allow an optimal number of threaded workers to start. 
    Jobs created can be killed via the -cleanup switch or by closing host window.
.EXAMPLE
    .\CPUStressTest.ps1 -CorePercent 50
.PARAMETER CorePercent
    Whole-number value representing a percentage (ex, "75" for 75%). This percent will be applied to the
    number of cores on the machine, and spawn that many threads.
.PARAMETER Cleanup
    Cleans up jobs from prior executions.
.INPUTS

.NOTES
    If the machine you are using only has one core, it will be set to 100% reuardless of specified
    CorePercent.
#>

[cmdletbinding(
        SupportsShouldProcess=$True,
        ConfirmImpact = 'High',
        DefaultParameterSetName='SpinUp',
        PositionalBinding="CorePercent"
)]

param(
    [parameter(
            mandatory=$true,
            ParameterSetName='SpinUp',
            Position=0
    )]
    [int]$CorePercent,
    [parameter(
            mandatory=$false,
            ParameterSetName='SpinDown'
    )]
    [switch]$Cleanup
)

if ($Cleanup){
    Write-Host "Stopping jobs"
    Stop-Job -Name "CPUStressTest*"
    $jobList = Get-Job -Name "CPUStressTest*"
    Get-Job  -Name "CPUStressTest*" | Receive-Job -AutoRemoveJob -Wait
    return $jobList
}

$cpuCount = (Get-WmiObject -class Win32_processor).NumberOfLogicalProcessors
$threadCount = [math]::floor($cpuCount*($CorePercent/100))

# This is for VMs that only happen to have one core.
if($threadCount -eq 0){
  $threadCount = 1
}

Write-Host "Utilize Core Percent:  $CorePercent"
Write-Host "Logical Core Count:    $cpuCount"
Write-Host "Worker Thread Count:   $threadCount"

Write-Warning "Using CTRL+C will not end background execution of worker threads."
Write-Warning "To kill worker threads, close this host window, or use .\CPUStressTest.ps1 -Cleanup"

if ($PSCmdlet.ShouldProcess($CorePercent)){
    for ($t = 1; $t -le $threadCount; $t++){
        $nul = Start-Job -Name "CPUStressTest_$t" -ScriptBlock {
            $result = 1
            for ($i = 0; $i -lt 2147483647; $i++){
                $result *= $i
            }
        }
    }
    Write-Host "$threadCount jobs started!"
    $jobList = Get-Job -Name "CPUStressTest*"
}
return $jobList
