The guide contains continued setup information for the Caldera port of the Turla Carbon scenario. If you have not yet set up Caldera, please refer to the [initial setup instructions](README.md) first.

# STARTING THE CONTROL SERVER
On the attacker machine, open a new terminal window and run the following to start the C2 server: 
```
cd caldera/plugins/emu/data/adversary-emulation-plans/turla/Resources/control_server
rm logs.txt
sudo ./controlServer -c ./config/turla_day1.yml
```
Ensure that the Carbon & Epic handlers start up before continuing to the next step. 

# FACT SETUP

Before running the operation, you will need to make sure that the Turla fact source is properly configured for your environment. While default fact values are provided, they will need to be replaced by the appropriate values specific to your testing environment. On the left menu, under `Configuration`, select `fact sources`. Under the "Select a source" drop-down menu, select `Turla - Carbon (Emu)`, which is the fact source for the Turla adversary. From there, update the following facts as needed:

- `network.domain.name`:  The network domain name for initial target system.
- `first.target.ip`: The IP address of the first target host.
- `first.target.user`: The username of the first target host.
- `first.target.password`: The password of the first target host.
- `first.target.host`: The hostname of the first target host.
- `second.target.ip`:  The IP address of the second target host.
- `second.target.user`: The username of the second target host.
- `second.target.password`: The password of the second target host.
- `second.target.host`: The hostname of the second target host.
- `third.target.ip`: The IP address of the third target host.
- `third.target.user`: The username of the third target host.
- `third.target.password`: The password of the third target host.
- `third.target.host`: The hostname of the third target host.
- `third.target.ntlm`: The NTLM hash for the third target user.
- `apache.server.ip`: The IP address of the Apache server.
- `attacker.host.ip`: The IP address of the attacker's host.
- `first.epic.id`: The first EPIC implant ID.
- `second.epic.id`: The second EPIC implant ID.
- `first.carbon.id`: The first Carbon implant ID.
- `second.carbon.id`: The second Carbon implant ID.
- `third.carbon.id`: The third Carbon implant ID.

Generally, it’s only possible to task a Caldera agent which is alive and actively checking in with the Caldera server. However, due to the integration between the `evalsc2client.py` and the Caldera Emu plugin in this port, the user is effectively tasking the Sandcat agent to task `evalsc2client.py` to task an implant through the Control Server, which makes it possible to task an implant that is not active. Therefore, a Caldera requirement was implemented to prevent an ability from executing if the implant tasked in that ability was not actively beaconing in. This requirement uses the facts for the EPIC and Carbon implant IDs, which are listed above.

# RUNNING THE OPERATION

- After adjusting the fact source as needed, select operations from the left menu, under "Campaigns".
- Select "+ Create Operation" to the right of the drop-down menu.
- Add in an appropriate name for your operation.
- For the adversary profile, select `Turla - Carbon (Turla)`.
- For the Fact Source, select `Turla - Carbon (Emu)`.
- Select Advanced to expand the Advanced configurations.
- For Group, make sure All Groups is selected.
- For the Planner, select the atomic planner.
- Make sure the plain-text obfuscator is selected.
- For Autonomous, make sure "Run Autonomously" is selected.
- For the Parser, select "Do not use default parsers".
- For Auto-close, you can decide whether or not you want the operation to auto-terminate or stay open until someone terminates the operation.
- For Run state, make sure "Run immediately" is selected.
- Adjust Jitter as needed if you want the operation steps to occur with greater or lesser frequency.
- Keep visibility at 51.
- When ready, hit the Start button and wait for your operation to complete.

# TERMINATING THE OPERATION

Press the stop button in the operation GUI to finish the operation. Terminate the Kali agent from the GUI or RDP/SSH into the machine to stop the agent processes.

## Cleanup
To remove artifacts following operation, follow the [Cleanup](./../../Resources/cleanup/README.md#carbon-scenario) instructions for the Carbon Scenario.

# DEVIATIONS FROM THE ORIGINAL EMULATION PLAN

## Step 1
 - Rather than navigating to `https://brieftragerin.skt.local/owa`, logging in, and clicking the link in the email from `noreply@sktlocal.it`, the port will download `NTFVersion.exe` by navigating directly to `http://anto-int.com/NTFVersion.exe` in the Edge browser. 

## Step 8
- The password `Password2!` is hardcoded into the ability to ssh into the Apache server. If your password is not `Password2!`, you will need to edit the `xdotool` commands in the ability named "Adalwolfa types keylogged data (User)" to include your specific password.

- The port does not include `Adalwolfa` opening the Edge browser and navigating to `http://kagarov/index.html`. It also does not include `Adalwolfa` editing the `/var/www/html/index.html` file.

