<#
.SYNOPSIS
    This script will perform a number of actions generating low level telemetry for sensors to capture.
    ** Run in USER context **

.DESCRIPTION
    Use -ExecuteAll switch to run all data generators:
    .\telemetry-generator.ps1 -ExecuteAll

    For isolated generation, specify generators as switches:
    .\telemetry-generator.ps1 -WriteFile -ReadFile -DeleteFile

    USER context required for visibility into ExecuteAdminIntegrity generator.

    Order matters for generators when specifying switches. For instance, you can not use -ReadFile before -WriteFile.

.PARAMETER Help
    Print descriptions of generators

.PARAMETER ExecuteAll
    Switch to run all generators

.PARAMETER WriteFile
    Switch to write file to `$($Env:SystemRoot)\Temp\WriteFile-Test.ps1` with content `Write-Host "[*] WriteFile Test"`

.PARAMETER ReadFile
    Switch to read file at `$($Env:SystemRoot)\Temp\WriteFile-Test.ps1`

.PARAMETER DeleteFile
    Switch to delete file at `$($Env:SystemRoot)\Temp\WriteFile-Test.ps1`

.PARAMETER WriteKey
    Switch to write regkey to `HKCU:\Software\Microsoft\.Test`" with content `Test`

.PARAMETER ReadKey
    Switch to read regkey at `HKCU:\Software\Microsoft\.Test`

.PARAMETER DeleteKey
    Switch to delete regkey at `HKCU:\Software\Microsoft\.Test`

.PARAMETER NetworkConnection
    Switch to generate network traffic by making an HTTPS GET request to `https://httpbin.org/get`

.PARAMETER CreateProcess
    Switch to create new cmd.exe process via Start-Process

.PARAMETER ExecutePowerShell
    Switch to execute PowerShell script from a .ps1 file via powershell.exe -File

.PARAMETER PowerShellTest
    Helper switch for ExecutePowerShell generator. Not a generator itself.

.PARAMETER ExecuteWMI
    Switch to execute WMI query in the `root\cmiv2` namespace for `Win32_BIOS` information

.PARAMETER ExecuteAPI
    Switch to execute CreateProcess from the Windows API by importing kernel32.dll through PowerShell
    Source File: `$($Env:SystemRoot)\System32\notepad.exe`

.PARAMETER ExecuteService
    Switch to restart the Audiosrv service
    NOTE: This requires admin. Achieved through -Verb RunAs in new PowerShell process

.PARAMETER LogonValid
    Switch to generate valid logon event via `net use q: \\127.0.0.1\IPC$` with provided valid credentials
    Ensure `Audit Account Logon Events` and `Audit Logon Events` are enabled for event log visibility

.PARAMETER LogonInvalid
    Switch to generate invalid logon event via `net use q: \\127.0.0.1\IPC$` with invalid credentials
    Ensure `Audit Account Logon Events` and `Audit Logon Events` are enabled for event log visibility

.PARAMETER ExecuteAdminIntegrity
    Switch to have calc.exe run with Admin integrity level via -Verb RunAs

.NOTES
    To add generators:
     - Create a new function 
     - Create parameter with the same name
     - Add funciton to ExecuteAll
     - Add .PARAMETER descriptor to Get-Help definition
#>

param(
    [parameter()]
    [switch]$Help,
    [parameter()]
    [switch]$ExecuteAll,
    [parameter()]
    [switch]$WriteFile,
    [parameter()]
    [switch]$ReadFile,
    [parameter()]
    [switch]$DeleteFile,
    [parameter()]
    [switch]$WriteKey,
    [parameter()]
    [switch]$ReadKey,
    [parameter()]
    [switch]$DeleteKey,
    [parameter()]
    [switch]$NetworkConnection,
    [parameter()]
    [switch]$CreateProcess,
    [parameter()]
    [switch]$ExecutePowerShell,
    [parameter()]
    [switch]$PowerShellTest,
    [parameter()]
    [switch]$ExecuteWMI,
    [parameter()]
    [switch]$ExecuteAPI,
    [parameter()]
    [switch]$ExecuteService,
    [parameter()]
    [switch]$LogonValid,
    [parameter()]
    [switch]$LogonInvalid,
    [parameter()]
    [switch]$ExecuteAdminIntegrity
)

function WriteFile{
    Write-Host "[*] Atempting to write to $($Path)" 
    Set-Content -Path $Path -Value "Write-Host `"[*] WriteFile Test`""
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function ReadFile{
    Write-Host "[*] Atempting to read $($Path)" 
    if(!$(Test-Path -Path $Path)){
        Write-Host -ForegroundColor "Red" "[-] $($MyInvocation.MyCommand) - $($Path) Does not exist - Skipping..."
        return
    }
    Get-Content -Path $Path 1>$NULL
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function DeleteFile{
    Write-Host "[*] Atempting to delete $($Path)" 
    if(!$(Test-Path -Path $Path)){
        Write-Host -ForegroundColor "Red" "[-] $($MyInvocation.MyCommand) - $($Path) Does not exist - Skipping..."
        return
    }
    Remove-Item -Path $Path
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function WriteKey{
    Write-Host "[*] Atempting to write to $($RegPath).Test"
    New-ItemProperty -Path $RegPath -Name "Test" -Value "Test" -Force 1>$NULL
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function ReadKey{
    Write-Host "[*] Atempting to read $($RegPath).Test" 
    Get-ItemProperty -Path $RegPath -Name "Test" 1>$NULL
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function DeleteKey{
    Write-Host "[*] Atempting to delete $($RegPath).Test" 
    Remove-ItemProperty -Path $RegPath -Name "Test"
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function NetworkConnection{
    $Uri = "https://httpbin.org:443/get"
    Write-Host "[*] Atempting connection to $($Uri)" 
    Invoke-WebRequest -Uri $Uri -UseBasicParsing
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function CreateProcess{
    Write-Host "[*] Atempting to spawn CMD process" 
    $cmdPID = (Start-Process -FilePath "$($Env:SystemRoot)\System32\cmd.exe" -ArgumentList "/c 'echo `"executing CreateProcess`"'" -passthru).ID
    WriteStatus($MyInvocation.MyCommand)
    if($cmdPID){
        Write-Host -ForegroundColor "Green" "[*] cmd.exe Process PID: $($cmdPID)"
    }
    Sleep 1
}

function ExecutePowerShell{
    Write-Host "[*] Atempting to spawn PowerShell process" 
    Start-Process -FilePath "$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList "-File", "$($MyInvocation.ScriptName)", "-PowerShellTest"
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function ExecuteWMI{
    Write-Host "[*] Atempting WMI query" 
    Get-WmiObject -namespace root\cimv2 -query "SELECT * FROM Win32_BIOS" 1>$NULL 
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function ExecuteAPI{
    Write-Host "[*] Atempting Execution of CreateProcess Win API via kernel32.dll to launch Notepad.exe" 
    # https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-1/
    # https://stackoverflow.com/questions/16686122/calling-createprocess-from-powershell
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO
{
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public STARTF dwFlags;
    public ShowWindow wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
    public int length;
    public IntPtr lpSecurityDescriptor;
    public bool bInheritHandle;
}

[Flags]
public enum CreationFlags : int
{
    NONE = 0,
    DEBUG_PROCESS = 0x00000001,
    DEBUG_ONLY_THIS_PROCESS = 0x00000002,
    CREATE_SUSPENDED = 0x00000004,
    DETACHED_PROCESS = 0x00000008,
    CREATE_NEW_CONSOLE = 0x00000010,
    CREATE_NEW_PROCESS_GROUP = 0x00000200,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    CREATE_SEPARATE_WOW_VDM = 0x00000800,
    CREATE_SHARED_WOW_VDM = 0x00001000,
    CREATE_PROTECTED_PROCESS = 0x00040000,
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
    CREATE_DEFAULT_ERROR_MODE = 0x04000000,
    CREATE_NO_WINDOW = 0x08000000,
}

[Flags]
public enum STARTF : uint
{
    STARTF_USESHOWWINDOW = 0x00000001,
    STARTF_USESIZE = 0x00000002,
    STARTF_USEPOSITION = 0x00000004,
    STARTF_USECOUNTCHARS = 0x00000008,
    STARTF_USEFILLATTRIBUTE = 0x00000010,
    STARTF_RUNFULLSCREEN = 0x00000020,  // ignored for non-x86 platforms
    STARTF_FORCEONFEEDBACK = 0x00000040,
    STARTF_FORCEOFFFEEDBACK = 0x00000080,
    STARTF_USESTDHANDLES = 0x00000100,
}

public enum ShowWindow : short
{
    SW_HIDE = 0,
    SW_SHOWNORMAL = 1,
    SW_NORMAL = 1,
    SW_SHOWMINIMIZED = 2,
    SW_SHOWMAXIMIZED = 3,
    SW_MAXIMIZE = 3,
    SW_SHOWNOACTIVATE = 4,
    SW_SHOW = 5,
    SW_MINIMIZE = 6,
    SW_SHOWMINNOACTIVE = 7,
    SW_SHOWNA = 8,
    SW_RESTORE = 9,
    SW_SHOWDEFAULT = 10,
    SW_FORCEMINIMIZE = 11,
    SW_MAX = 11
}

public static class Kernel32
{
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreateProcess(
        string lpApplicationName, 
        string lpCommandLine, 
        ref SECURITY_ATTRIBUTES lpProcessAttributes, 
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles, 
        CreationFlags dwCreationFlags, 
        IntPtr lpEnvironment,
        string lpCurrentDirectory, 
        ref STARTUPINFO lpStartupInfo, 
        out PROCESS_INFORMATION lpProcessInformation);

}
'@

    $exe = "$($Env:SystemRoot)\System32\notepad.exe"

    $si = New-Object STARTUPINFO
    $pi = New-Object PROCESS_INFORMATION

    $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
    $si.wShowWindow = [ShowWindow]::SW_SHOW

    $pSec = New-Object SECURITY_ATTRIBUTES
    $tSec = New-Object SECURITY_ATTRIBUTES
    $pSec.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($pSec)
    $tSec.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($tSec)

    $Status = [Kernel32]::CreateProcess($exe, $null, [ref] $pSec, [ref] $tSec, $false, [CreationFlags]::NONE, [IntPtr]::Zero, $Env:SystemRoot, [ref] $si, [ref] $pi)

    #[System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    $pi

    if(!$Status){
        Write-Error "[!] Could not execute CreateProcess via kernel32.dll! `n Exe: $($exe)"
        WriteStatus($MyInvocation.MyCommand)
    } else {
        WriteStatus($MyInvocation.MyCommand)
    }

    Sleep 1
}

function ExecuteService{
    $Service = "Audiosrv"

    Write-Host "[*] Atempting to restart service: $($Service)" 
    Start-Process -FilePath "$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList "Restart-Service", "-Name", "$($Service)" -Verb RunAs
    
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function LogonValid{    
    $Creds = Get-Credential -Message "Please enter valid local system credentials for $($MyInvocation.MyCommand) generator..."

    Write-Host "[*] Generating Logon Event"

    net use q: \\127.0.0.1\IPC$ /user:$Creds.username $Creds.password 2>$NULL
    Write-Host "[*] Logon Event Generated"
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function LogonInvalid{
    Write-Host "[*] Generating Logon Event"

    net use q: \\127.0.0.1\IPC$ /user:$Env:UserName "InvalidPasswordForFailedLogon" 2>$NULL
    Write-Host "[*] Logon Event Generated"
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function ExecuteAdminIntegrity{
    Write-Host "[*] Atempting to spawn calc.exe with admin integrity level" 
    Start-Process -FilePath "$($Env:SystemRoot)\System32\calc.exe" -Verb RunAs
    WriteStatus($MyInvocation.MyCommand)
    Sleep 1
}

function ExecuteAll{
    Write-Host -ForegroundColor "Green" "[*] powershell.exe Process PID: $($PID)"
    Write-Host "[*] Executing Test 0: LogonValid"
    LogonValid
    Write-Host "[*] Executing Test 1: LogonInvalid"
    LogonInvalid
    Write-Host "[*] Executing Test 2: CreateProcess"
    CreateProcess
    Write-Host "[*] Executing Test 3: ExecutePowerShell"
    ExecutePowerShell
    Write-Host "[*] Executing Test 4: WriteFile"
    WriteFile
    Write-Host "[*] Executing Test 5: ReadFile"
    ReadFile
    Write-Host "[*] Executing Test 6: DeleteFile"
    DeleteFile
    Write-Host "[*] Executing Test 7: WriteKey"
    WriteKey
    Write-Host "[*] Executing Test 8: ReadKey"
    ReadKey
    Write-Host "[*] Executing Test 9: DeleteKey"
    DeleteKey
    Write-Host "[*] Executing Test 10: NetworkConnection"
    NetworkConnection
    Write-Host "[*] Executing Test 11: ExecuteAPI"
    ExecuteAPI
    Write-Host "[*] Executing Test 12: ExecuteAdminIntegrity"
    ExecuteAdminIntegrity
    Write-Host "[*] Executing Test 13: ExecuteWMI"
    ExecuteWMI
    Write-Host "[*] Executing Test 14: ExecuteService"
    ExecuteService

    Write-Host -ForegroundColor "Green" @"
`n--------------------------------------
        [+] All Tests Complete
--------------------------------------
"@

}

# This function is paired with ExecutePowerShell to generate PowerShell execution of a file
function PowerShellTest{
    Write-Host "[*] PowerShell File Execution Output"
    Exit
}

function WriteStatus{
    param([string]$FuncName)

    if(!$?){
        Write-Host -ForegroundColor "Red" "$(Get-Date -Format HH:mm:ss.fff) - [!] $($FuncName) failed! See Error Output..."
    } else {
        Write-Host -ForegroundColor "Green" "$(Get-Date -Format HH:mm:ss.fff) - [+] $($FuncName) success!"
    }
}

function Help{
    Get-Help $MyInvocation.ScriptName -Detailed
}

# Global Paths
$Path = "$($Env:SystemRoot)\Temp\WriteFile-Test.ps1"
$RegPath = "HKCU:\Software\Microsoft\"

# Execute all functions provided as parametes
$KeyArgs = $PSCmdlet.MyInvocation.BoundParameters.Keys 
if($KeyArgs -ne {}){
    $KeyArgs | ForEach-Object {&$_}
} else {
    # Printing Help information is default
    Help
}
