
# Screen Recorder: windows/post/gather/screen_spy

The Metasploit screen_spy module records the user's screen by screenshot'ing the user desktop.

Screenshots are taken using the following Windows API functions:

```
// get handle to necessary GUI/window objects
OpenInputDesktop
GetThreadDesktop
SetThreadDesktop
GetDesktopWindow

// get device context (i.e. metadata describing the desktop image)

GetDC

// convert device-context metadata into an image file
CreateCompatibleBitmap
```

Screenshots do not appear to be dropped to disk; instead, the screenshots are stored in a buffer in memory, and are sent to the attack platform over the Meterpreter C2 channel.

This module closely emulates the screen-recording implementation seen in Carbanak-malware source code.

### References:

1. https://github.com/rapid7/metasploit-payloads/blob/master/c/meterpreter/source/extensions/espia/screen.c

2. https://github.com/Aekras1a/Updated-Carbanak-Source-with-Plugins/blob/d40434bfa3933b5980babfb1f5552659d73e7b9d/Carbanak%20-%20part%201/botep/WndRec/source/video.cpp

3. https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdc

# Meterpreter Keylogger 

This step is intended to emulate FIN7's use of the RDFSNIFFER malware.

We inject the Meterpreter keylogger into process memory of mstsc.exe, which is the RDP client.

1. https://github.com/rapid7/metasploit-payloads/blob/18ed237c1d9ae70030d1b01e64eb67b2c75fa9db/c/meterpreter/source/extensions/stdapi/server/ui/keyboard.c
