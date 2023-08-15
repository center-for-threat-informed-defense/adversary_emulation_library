# Scenario Overview

## 🗺️ Legend
This document is intended to be used as a operational guide for a purple team operation. 

Based on the CTI Emulation Plan, each step includes the following information:
- :microphone: **Voice Track** - Summuary of actions that are completed in this step
- :biohazard: **Procedures** - Red team operator instructions & commands to execute with expected output
- :moyai: **Source Code** - Links to the source code that executes the specifc actions throughout the step
- :microscope: **Cited Intelligence** - Key reporting leveraged in this step

In-line Symbols:
* :bulb: - callout notes
* :heavy_exclamation_mark: - extremely important note
* :arrow_right: - Switching to another session
* :o: - Sign out of something
* 💖 - Red Team Notes
* 💙 - Blue Team Notes

## 🌊💮 Emulation 
This scenario emulates OceanLotus TTPs based primarily on two malware specimens either 
used by or associated with the OceanLotus actors:

1. Rota Jakiro
1. OceanLotus.abcdef

---
## Step 0 - Setup

### :microphone: Voice Track

Assume download of conkylan.app (unicorn in Vietnamese) resides on the downloads folder. 


---

### :biohazard: Procedures

* :bulb: Due to MITRE restrictions on AWS, you cannot connect directly over required port to the Mac instance. 
To get around restriction, you must setup an SSH tunnel. 
Note: Only one user can have an active VNC session at a time.
Note 2: Use the ec2-user on the Mac to establish the tunnel.
1. Setup SSH Tunnel to forward port 5900 to localhost

You can also add -i to specify a private key
The result should be an active SSH session, with port 5900 on the Mac forwarded to port 5900 on your local machine.

change the username to whatever user you want to use: 
ssh -L 5900:localhost:5900 ec2-user@10.90.30.22
2. Connect over VNC

From your lifecycle/Mac:
vncviewer localhost:5900

If you use a different local port for the ssh tunnel, update the port here to match




Result:


* Check the file exists:
```
ls /var/www/html
```


## Step 1 - Initial Compromise and Persistence

### :microphone: Voice Track


---

### :biohazard: Procedures


### :moyai: Source Code
*   Dropper: [Rota](../Resources/Rota)



<br>

### :microscope: Cited Intelligence


<br>


## Step 2 - Workstation Discovery

---
:red_circle: End of Scenario. 
