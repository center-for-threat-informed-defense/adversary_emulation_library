# ---------------------------------------------------------------------------
# Carbon Orchestrator and CAST-128 encryption/decryption utility build script

# Copyright 2023 MITRE Engenuity. Approved for public release. Document number CT0005.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

# This project makes use of ATT&CK®
# ATT&CK Terms of Use - https://attack.mitre.org/resources/terms-of-use/ 

# Usage: build.ps1
# Must be run from inside the "Orchestrator" folder

# Revision History:

# --------------------------------------------------------------------------- 


if (Test-Path -Path .\bin\runner.exe -PathType Leaf) { # if the runner exists, delete
    Remove-Item .\bin\runner.exe
}

if (Test-Path -Path .\bin\MSSVCCFG.DLL -PathType Leaf) { # if the main dll exists, delete
    Remove-Item .\bin\MSSVCCFG.DLL
}

Write-Host "Building runner"
x86_64-w64-mingw32-g++ -static -std=c++20 -lstdc++fs -Wall -Wextra -Werror -o bin/runner.exe test/testdllrunner.cpp # compile the runner exe
Write-Host "Building orchestrator"
x86_64-w64-mingw32-g++ -I include/ -I "$env:MINGW64_ROOT\include\cryptopp" -static -shared -std=c++20 -lstdc++fs -Wall -Wextra -Werror -o bin/MSSVCCFG.dll src/*.cpp -lWinInet -L "$env:MINGW64_ROOT\lib" -l cryptopp # compile the main dll
Write-Host "Building config encryptor"
x86_64-w64-mingw32-g++ -I include/ -I "$env:MINGW64_ROOT\include\cryptopp" -static -std=c++20 -lstdc++fs -Wall -Wextra -Werror -o bin/configEncrypt.exe test/config_encrypt.cpp -lWinInet -L "$env:MINGW64_ROOT\lib" -l cryptopp
Write-Host "Building decryptor"
x86_64-w64-mingw32-g++ -I include/ -I "$env:MINGW64_ROOT\include\cryptopp" -static -std=c++20 -lstdc++fs -Wall -Wextra -Werror -o bin/castDecrypt.exe test/castDecrypt.cpp -lWinInet -L "$env:MINGW64_ROOT\lib" -l cryptopp # compile the decryptor

Write-Host "Sripping symbols from orchestrator"
strip -s .\bin\MSSVCCFG.dll # remove the symbols from the built orchestrator dll

Write-Host "Check that symbols have been stripped from the orchestrator"
objdump --syms .\bin\MSSVCCFG.dll # check the symbols table to ensure they have been removed for orchestrator dll