#=============================================================================================
#
#       Filename:  drop_emotet_stage1_test.ps1
#
#    Description:  This program tests functionality of drop_emotet_stage1.vbs.
#   
#        Version:  1.1
#        Created:  March 1st, 2021
#
#      Author(s):  Michael C. Long II
#   Organization:  MITRE Engenuity
#
#  References(s): N/A
#
#=============================================================================================

#===============================================================================
#   Console Output functions
#===============================================================================
function Write-Failure() {
    param (
        $output_received,
        $output_expected
    )
    Write-Host "-------------------------------------------------"
    Write-Host "Test Failed!!!" -ForegroundColor Red
    Write-Host "-------------------------------------------------"
    Write-Host "[Received Output]:" -ForegroundColor Yellow
    Write-Host $output_received
    Write-Host "-------------------------------------------------"
    Write-Host "[Output Expected]:" -ForegroundColor Yellow
    Write-Host $output_expected
    Write-Host "-------------------------------------------------"
    Exit
}

function Write-Success() {
    Write-Host "....Test Passed!`n" -ForegroundColor Green
}

function Write-TestInfo() {
    param (
        $message
    )
    Write-Host $message -ForegroundColor Yellow
}

#===============================================================================
#   Setups and Tear Downs
#===============================================================================
function Start-WebServer() {
    Start-Process cmd.exe -ArgumentList "/C python -m http.server --bind 127.0.0.1 8080"
    Start-Sleep 1
}

function Stop-WebServer() {
    Start-Sleep 2
    Stop-Process -Name python
}

function Remove-TestDir($test_dir) {
    Remove-Item -Recurse -Force $test_dir
}

#===============================================================================
#   Unit Tests
#===============================================================================

function Invoke-UnitTest1 {
    Write-TestInfo "[Test 1]: drop_emotet_stage1.vbs creates whoami.exe process using WMI"
    $got = cscript.exe ..\drop_emotet_stage1.vbs whoami.exe
    $want = "Call to 'Create_Process_with_WMI' succeeded with exit code:  0"
    if (-Not $got.Contains($want)) {
        Write-Failure -output_received $got -output_expected $want
    }
    Write-Success        
}

function Invoke-UnitTest2 {
    Write-TestInfo "[Test 2]: drop_emotet_stage1.vbs throws graceful error when given non-existent process"
    $got = cscript.exe ..\drop_emotet_stage1.vbs this-is-not-real.exe
    $want = "Call to 'Create_Process_with_WMI' succeeded with exit code:  9"
    if ($got.Contains($want)) {
        Write-Failure -output_received $got -output_expected $want
    }
    Write-Success
}

function Invoke-UnitTest3 {
    Write-TestInfo "[Test 3]: drop_emotet_stage1.vbs executes encoded PowerShell 1 liners"
    $encoded_powershell_cmd = "powershell.exe -EncodedCommand ZQBjAGgAbwAgACIARABvAHIAbwB0AGgAeQAiAA=="
    $got = cscript.exe ..\drop_emotet_stage1.vbs $encoded_powershell_cmd
    $want = "Microsoft (R) Windows Script Host Version 5.812 Copyright (C) Microsoft Corporation. All rights reserved.  Call to 'Create_Process_with_WMI' succeeded with exit code:  0"
    if ($got.Contains($want)) {
        Write-Failure -output_received $got -output_expected $want
    }
    Write-Success
    
}

function Invoke-UnitTest4 {
    Write-TestInfo "[Test 4]: obfuscate_stage1_dropper.py works"

    # Setup test
    Start-WebServer

    # we write test_program.exe to this location
    $directory = $env:APPDATA + "\" + "Testing"
    

try {
    # generate obfuscated payload
    python ..\obfuscators\obfuscate_stage2_dropper.py -c test_config.yaml -i ..\drop_emotet_stage2.ps1 -o encoded_emotet_stage2_dropper.ps1
    python ..\obfuscators\obfuscate_stage1_dropper.py -c test_config.yaml -i encoded_emotet_stage2_dropper.ps1 -j ..\drop_emotet_stage1.vbs -o tmp.vbs
    cscript.exe ..\obfuscators\obfuscate_vbs.vbs tmp.vbs
    
    # execute dropper script to verify the entire system works
    cscript.exe obfuscated_emotet_dropper.vbs
}
catch {
    Write-Failure -output_expected "NIL" -output_received $_.Exception.Message
}   
    Write-Success

    # Tear down test and delete artifacts
    Stop-WebServer
    Remove-Item $directory\test_program.exe
    Remove-Item $directory
    Remove-Item tmp.vbs
    Remove-Item obfuscated_emotet_dropper.vbs
    Remove-Item encoded_emotet_stage2_dropper.ps1
}

Invoke-UnitTest1
Invoke-UnitTest2
Invoke-UnitTest3
Invoke-UnitTest4