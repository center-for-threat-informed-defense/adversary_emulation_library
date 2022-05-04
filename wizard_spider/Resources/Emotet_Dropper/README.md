# Emotet Dropper

## Overview

This folder contains files used to generate an emotet dropper.

The dropper works as follows:

1. Word document invokes VBA code via AutoOpen

2. AutoOpen macro downloads "adb.vbs" to %AppData% over 192.168.0.4:8080 / HTTP.

3. AutoOpen macro executes adb.vbs with cscript.

4. adb.vbs downloads a second-stage dropper; the dropper is heavily obfuscated.

5. The second stage VBS code executes base64 encoded PowerShell code.

6. The PowerShell code downloads EmotetClientDLL.dll over 192.168.0.4:443 / HTTPS and writes to disk at %AppData%\adb.dll

7. The PowerShell code executes adb.dll via rundll32.exe and Control_RunDLL function

## Quick Start

Upload `ChristmasCard.docx` to your intended target.

Open `ChristmasCard.docx` - it should download/execute the Emotet DLL, and send C2 connections to 192.168.0.4:80 / HTTP.

## Usage

0. Run this script on Windows to generate an obfuscated VBS payload:

```
.\generate_emotet_dropper.ps1
```

1. Copy obfuscated_emotet_dropper.vbs to the control server at this path:

```
wizard_spider/Resources/control_server/files/
```

2. Now create a new word document

3. In the word document, go to `View` > `Macros` > `Record Macro` > create a new Macro named `AutoOpen` and store it the document"

4. Hit `OK` and stop the recording under `Macros`

5. Go to `View` > `View Macros` > Select and edit `AutoOpen` macro

6. Paste the source code from `vba_macro_code.vbs` into the macro

7. Upload the word document to the intended target.

The payload should fire automatically after opening the document.

## Dependencies

Install Python3, pip, and PyYaml on your Windows system

```
pip install pyyaml
```

Make sure your attack platform has cloned the Wizard Spider repo and has the control_server folder.
