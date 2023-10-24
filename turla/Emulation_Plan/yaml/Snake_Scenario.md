The guide contains continued setup information for the Caldera port of the Turla Snake scenario. If you have not yet set up Caldera, please refer to the [initial setup instructions](README.md) first.

# PREPARING THE TARGETS 

1. Start by logging into the second target host (file server) as the domain admin user. Then, disconnect the RDP (do not log off). This is required for Step 16 credential dumping to succeed.
1. Log every other target user into their intended workstation and open Edge at least once to ignore any first time prompts. Log out of sessions.
1. Copy `Microsoft.Exchange.WebServices.dll` from an existing Exchange server to `turla/Resources/caldera_port`.

# STARTING THE CONTROL SERVER

On the attacker machine, open a new terminal window and run the following to start the C2 server: 
```
cd caldera/plugins/emu/data/adversary-emulation-plans/turla/Resources/control_server
rm logs.txt
sudo ./controlServer -c ./config/turla_day2.yml
```
Ensure the EPIC, Snake, and LightNeuron handlers start up before continuing to the next step. 

# FACT SETUP

Before running the operation, you will need to make sure that the Turla fact source is properly configured for your environment. While default fact values are provided, they will need to be replaced by the appropriate values specific to your testing environment. On the left menu, under `Configuration`, select `fact sources`. Under the "Select a source" drop-down menu, select `Turla - Snake (Emu)`, which is the fact source for the Turla adversary. From there, update the following facts as needed:

- `network.domain.name`:  The network domain name for initial target system.
- `first.target.ip`: The IP address of the first target host.
- `first.target.user`: The username of the first target host.
- `first.target.password`: The password of the first target host.
- `second.target.ip`:  The IP address of the second target host.
- `second.target.user`: The username of the second target host.
- `second.target.password`: The password of the second target host.
- `second.target.host`: The hostname of the second target host.
- `third.target.ip`: The IP address of the third target host.
- `third.target.user`: The username of the third target host.
- `third.target.password`: The password of the third target host.
- `third.target.host`: The hostname of the third target host.
- `fourth.target.host`: The hostname of the fourth target host.
- `file.server.admin`: The username of the file server admin.
- `domain.admin.ntlm`: The NTLM of a domain admin.
- `domain.admin.user`: The username of a domain admin.
- `new.domain.user`: The username of the new domain user.
- `new.domain.password`: The password of the new domain user.
- `first.epic.id`: The first EPIC implant ID.
- `first.snake.id`: The first Snake implant ID.
- `second.snake.id`: The second Snake implant ID.
- `third.snake.id`: The third Snake implant ID.
- `lightneuron.implant.id`: The Lightneuron implant ID.

Generally, it’s only possible to task a Caldera agent which is alive and actively checking in with the Caldera server. However, due to the integration between the [`evalsc2client.py`](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/turla/Resources/control_server/evalsC2client.py) and the Caldera Emu plugin in this port, the user is effectively tasking the Sandcat agent to task `evalsc2client.py` to task an implant through the Control Server, which makes it possible to task an implant that is not active. Therefore, a Caldera requirement was implemented to prevent an ability from executing if the implant tasked in that ability was not actively beaconing in. This requirement uses the facts for the EPIC and Snake implant IDs, which are listed above.

Additionally, a separate Caldera requirement was implemented for the Lightneuron implant. This requirement will allow an ability to execute if the Lightneuron implant ID is listed in the agents tab of the Caldera Server GUI, even if the agent is dead and untrusted. The Lightneuron agent only sends one initial beacon to the Server, and is then considered a dead agent. This custom requirement will allow Lightneuron to be tasked despite that fact that it appears dead in the Caldera GUI.

# RUNNING THE OPERATION

- After adjusting the fact source as needed, select operations from the left menu, under "Campaigns".
- Select "+ Create Operation" to the right of the drop-down menu.
- Add in an appropriate name for your operation.
- For the adversary profile, select `Turla - Snake (Turla)`.
- For the Fact Source, select `Turla - Snake (Emu)`.
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
To remove artifacts following operation, follow the [Cleanup](./../../Resources/cleanup/README.md#snake-scenario) instructions for the Snake Scenario.

# DEVIATIONS FROM THE ORIGINAL EMULATION PLAN

## Step 11
 - User executes NTFVersion.exe via Run prompt instead of double clicking from Downloads folder.

 
