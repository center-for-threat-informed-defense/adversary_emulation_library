# README for User Execution of OneNote File (.one)

## Prerequisites

- OS: Built and tested on Windows 10
- Application: Microsoft OneNote

## Executing the Application

- The tool distribution contains a zip file containing the `Dot_One.exe` file.
- Double-click `Dot_One.exe`, which will:

1. Create an HTTP server, which acts as adversary infrastructure
2. Prompt user with `press enter to exit...` in a cmd window
3. Drop malicious `.one` file to disk and opens in OneNote
4. User is prompted to double-click the `Accept License` button, which serves as our phishing object
5. Once the button is pressed, a batch script runs in the background creating a popup
6. Embedded batch script queries fileserver for encoded base64 powershell command from file `README.md` to create a benign scheduled task for persistence
7. Pressing enter on the original cmd window will cleanup all files, close the httpserver, and delete the scheduled task

## Customizing the PowerShell Command

### Prerequisites

- Application: Microsoft Visual Studio

1. Use [this cyberchef link](https://gchq.github.io/CyberChef/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')&input=c2NodGFza3MgL0NyZWF0ZSAvRiAvU0MgTUlOVVRFIC9NTyAzIC9TVCAwNzowMCAvVE4gQ01EVGVzdFRhc2sgL1RSICJjbWQgL2MgZGF0ZSAvVCA%2BIEM6XFdpbmRvd3NcVGVtcFxjdXJyZW50X2RhdGUudHh0Ig), replacing the `input` with the desired PowerShell commands
2. Paste the `output` from CyberChef into a new file `README.md`
3. In Visual Studio, double-click the `Resource1.resx` file in Solution Explorer and replace the default `README.md` with your new version
4. Compile as normal
 
## Updating the .one file

### Prerequisites

- Application: Microsoft OneNote

1. Write a batch script that performs the desired actions
2. Open the `.one` file and drag the "Accept License" button to the side
3. Delete the `EULA.bat` files from under the button and replace with your custom batch file (Insert > File Attachment)
   * Note: You'll need to add the file multiple times to cover the surface area of the button
4. To make sure the button is on top of the scripts, right-click the button and move it to the foreground (Right-click > Order > Bring to Front)
