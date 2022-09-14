# Enabling VMWare Shared Folders in an Ubuntu VM

This documentation is written for Ubuntu 22.04.

It should apply to most 20.x LTS versions of Ubuntu as well.

The steps in this documentation are needed if you are using Ubuntu in a virtual machine
and need to build the `phpwrapper` executable for Linux in the VM.

1. Install open-vm-tools packages. Your VM may already have these installed.
   * `open-vm-tools`
   * `open-vm-tools-desktop` (if your installation has a GUI)

```
sudo apt-get install open-vm-tools open-vm-tools-desktop
```

2. Create the directory /mnt/hgfs - if it already exists, it must be empty.

```
sudo mkdir -p /mnt/hgfs
```

3. Add this line to `/etc/fstab`:

```
.host:/	/mnt/hgfs	fuse.vmhgfs-fuse	auto,allow_other	0	0
```

3. Create the text file `/etc/systemd/system/mnt-hgfs.mount` on the VM with this content:

```
[Unit]
Description=VMware mount for hgfs
DefaultDependencies=no
Before=umount.target
ConditionVirtualization=vmware
After=sys-fs-fuse-connections.mount

[Mount]
What=vmhgfs-fuse
Where=/mnt/hgfs
Type=fuse
Options=default_permissions,allow_other

[Install]
WantedBy=multi-user.target
```

3. Create the file `/etc/modules-load.d/open-vm-tools.conf` with this content,
   or add this line if the file already exists:

```
fuse
```

4. Enable the system service for hgfs:

```
sudo systemctl enable mnt-hgfs.mount
```

5. Make sure the `fuse` module is loaded using `modprobe`:

```
sudo modprobe -v fuse
```

6. Start the hgfs service or reboot the VM to start it then:

```
sudo systemctl start mnt-hgfs.mount
```

7. Mount the VMWare file system to `/mnt/hgfs`:

```
sudo mount -t fuse.vmhgfs-fuse .host:/ /mnt/hgfs -o allow_other
```

8. If you have already defined a shared folder in VMWare Player, it should appear in `/mnt/hgfs`.
   If not, shut down the VM, define the shared folder in thw VM's settings, and check for it after a restart.

## Appendix References - VMWare Documentation

The instructions in this section are a synthesis of the following articles, which may be useful for troubleshooting.

* [open-vm-tools and VMWare Shared Folders for Ubuntu Guests](https://gist.github.com/darrenpmeyer/b69242a45197901f17bfe06e78f4dee3)
* [Enabling HGFS Shared Folders on Fusion or Workstation hosted Linux VMs for open-vm-tools (74650)](https://kb.vmware.com/s/article/74650)
* [Install Open VM Tools](https://docs.vmware.com/en/VMware-Tools/11.3.0/com.vmware.vsphere.vmwaretools.doc/GUID-C48E1F14-240D-4DD1-8D4C-25B6EBE4BB0F.html)
