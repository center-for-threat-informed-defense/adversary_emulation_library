# Cleanup

## OSX.OceanLotus

1. From the Kali Linux machine, copy the cleanup script to the Mac host,
entering the password when prompted:
    ```
    cd /opt/oceanlotus/Resources/cleanup
    scp -i /home/kali/.ssh/id_rsa_ocean OSX.OceanLotus/cleanup_osx.oceanlotus.sh ec2-user@10.90.30.22:/tmp/cleanup_osx.oceanlotus.sh
    ```
   
1. SSH from the Kali Linux machine to the Mac host, entering the password when
prompted:
    ```
    ssh -i /home/kali/.ssh/id_rsa_ocean ec2-user@10.90.30.22
    ```
   
1. Using the SSH session, modify the file permissions of the cleanup script to be owned by `hpotter`:
    ```
    cd /tmp
    sudo chown -R hpotter /tmp/cleanup_osx.oceanlotus.sh
    ```
   
1. Switch user to `hpotter` then execute the cleanup script:
    ```
    sudo su hpotter
    ./cleanup_osx.oceanlotus.sh /Users/hpotter/Downloads
    ```
    
    Expected output:
    ```
    Identified executing directory as: /Users/hpotter/Downloads/

    [+] /Users/hpotter/Library/WebKit/com.apple.launchpad exists, removing...
      [+] /Users/hpotter/Library/WebKit/com.apple.launchpad was removed successfully
    [+] /Users/hpotter/Library/WebKit/b2NlYW5sb3R1czIz exists, removing...
      [+] /Users/hpotter/Library/WebKit/b2NlYW5sb3R1czIz was removed successfully
    [+] /Users/hpotter/Downloads//conkylan.doc exists, removing...
      [+] /Users/hpotter/Downloads//conkylan.doc was removed successfully
    [+] /tmp/store exists, removing...
      [+] /tmp/store was removed successfully
    [+] Persistence found, removing...
    /Users/hpotter/Library/LaunchAgents/com.apple.launchpad/com.apple.launchpad.plist: Operation now in progress
    [+] Unloaded LaunchAgent persistence
    [+] /Users/hpotter/Library/LaunchAgents/com.apple.launchpad directory exists, removing...
      [+] /Users/hpotter/Library/LaunchAgents/com.apple.launchpad directory was removed successfully
    [-] No /tmp/*.log files found
    [+] TextEdit found, killing...
    ```
1. Remove the cleanup script then exit `hpotter`'s session then the SSH session:
    ```
    rm /tmp/cleanup_osx.oceanlotus.sh
    exit
    exit
    ```

:information_source: **Note:** This script assumes successful execution of the
OSX.OceanLotus implant and installation of persistence via LaunchAgent. Any
unexpected output may imply certain areas of execution where not completed
successfully.


## Rota

1. From the Kali Linux machine, copy the cleanup script to the Mac host,
entering the password when prompted:
    ```
    cd /opt/oceanlotus/Resources/cleanup
    scp rota/cleanup_linux_rota.sh <Linux user>@<Linux IP>:/tmp/cleanup_linux_rota.sh
    ```
    | Password |
    | -------- |
    | <Linux user password> |
1. SSH from the Kali Linux machine to the Linux host, entering the password when
prompted:
    ```
    ssh <Linux user>@<Linux IP>
    ```
    | Password |
    | -------- |
    | <Linux user password> |
1. Using the SSH session, execute the cleanup script:
    ```
    cd /tmp
    ./cleanup_linux_rota.sh 
    ```

    Expected output:
    ```
    [+] Successfully removed au-tostart
    [+] Successfully removed .gvfsd folder
    [+] Successfully removed .dbus folder
    [+] Successfully removed persistence in bashrc
    [+] Successfully removed file locks
    [+] Successfully removed IPC Sharedmemory Key
    ```
1. Remove the cleanup script then exit the SSH session:
    ```
    rm /tmp/cleanup_linux_rota.sh
    exit
    ```

:information_source: **Note:** This script assumes successful execution of the
Rota Linux implant. Any unexpected output may imply certain areas of execution where not completed
successfully.
