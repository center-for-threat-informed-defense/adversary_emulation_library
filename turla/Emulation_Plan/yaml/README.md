# OVERVIEW

The Turla port contains two adversary profiles for each of the executed scenarios in MITRE Engenuity's ATT&CK® Evaluations: Enterprise - Round 5. **Follow the setup instructions below** and then navigate to the scenario-specific setup guides for the profile you would like to execute:

- [Carbon Scenario](Carbon_Scenario.md)
- [Snake Scenario](Snake_Scenario.md)

Information about each scenario can be found [here](../../Emulation_Plan/README.md).

# DEPENDENCIES

## CALDERA C2 Server
- Linux/Mac OS, 64-bit
- git commandline installed
- python3.8+ with pip3
- golang 1.17+
    - required for dynamic agent compilation
- Recommended hardware is 8GB+ RAM and 2+ CPUs

## Attacker Machine Dependencies
- Linux OS, 64-bit 
    - Kali recommended
    - Can be the same machine as the CALDERA C2 server
- Command-line tools
    - xfreerdp
    - xdotools
    - curl
    - urllib3
    - ncat (by Nmap)

# SETUP

## Download and Install CALDERA
Run the following on a Linux/Mac machine of your choice. This machine will act as your C2 server, or the "attacker" host. For the purposes of this walkthrough, the C2 server will have an IP address of `176.59.15.33`. 
```
git clone --depth 1 https://github.com/mitre/caldera.git --recursive
cd caldera
git checkout master && git pull
cp conf/default.yml conf/local.yml
cd plugins/emu
git checkout master && git pull
```

Add the `emu` plugin to your `conf/local.yml` configuration file. Feel free to enable or disable other plugins
by adding/removing them from the configuration file. You can also configure your user accounts and credentials if needed.
```
vi conf/local.yml
```

Download pip dependencies.
```
pip3 install --upgrade setuptools
pip3 install --upgrade pip
pip3 install -r requirements.txt
```

Download required payloads for `emu` plugin.
```
# from caldera/plugins/emu directory 

git checkout master && git pull
./download_payloads.sh
```

Run your C2 server from the caldera directory. This will unzip encrypted executables throughout the `adversary-emulation-library` and ingest its emulation plans.
```
# from caldera directory

python3 server.py --insecure --log DEBUG
```


## Compile Snake & Mimikatz Binaries

### Snake

:exclamation: Snake has not been included in this binaries.zip. Please visit the following
resources for building Snake and its components:
- [Snake Installer Build](../../Resources/Snake/SnakeInstaller/README.md#build)
- [Snake Build Script](../../Resources/Snake/buildall.ps1)

### Mimikatz

:exclamation: Mimikatz must be modified and compiled according to these [instructions](https://github.com/attackevals/turla/tree/public-release/Resources/Mimikatz#adjustments-made-to-mimikatz-pth-function). 

## Launch the Kali Agent

RDP to `176.59.15.33`, the Kali attacker host, as user `dev` with password `DevPass12345`. Launch the Kali agent by running the following command. You may need to modify the command so the server value matches your attacker host's IP address. 

:exclamation: Keep this RDP open as this will be leveraged by xfreerdp in the executed Caldera operation. Once the operation has been started, avoid interacting with the RDP to Kali. Clicking or switching windows within the Kali RDP will interfere with the user activity that is automated through Caldera.

```
cd /home/dev/caldera/plugins/emu/data/adversary-emulation-plans/turla/Resources/control_server;
server="http://176.59.15.33:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;
chmod +x splunkd;
./splunkd -server $server -group kali -v
```

Log into CALDERA's web GUI by accessing your C2 server address in a web browser (Chrome recommended), and using your credentials (default username is `red`, default password is `admin`).

On the left sidebar, under "Campaigns", click "agents" and confirm that you see the Kali agent beaconing in. 

For best results, make sure you don't have other agents currently beaconing in.
