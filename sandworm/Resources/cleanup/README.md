# Sandworm Scenario Cleanup Procedure

## Caladan

Upload Caladan cleanup script:

```bash
cd ~/
scp sandworm/Resources/cleanup/cleanup-caladan.sh fherbert@10.0.1.5:/tmp/cleanup-caladan.sh
```

Password:

`Whg42WbhhCE17FEzrqeJ`

Run the Caladan cleanup script:

```
ssh fherbert@10.0.1.5 "chmod 755 /tmp/cleanup-caladan.sh && sudo /tmp/cleanup-caladan.sh && shred /tmp/cleanup-caladan.sh"
```

:warning: if you see this error, just reboot Caladan and re-run the cleanup procedure.

`shred: /var/www/html/centreon_module_linux_app64: failed to open for writing: Text file busy`

Reboot Caladan

```
ssh fherbert@10.0.1.5 "sudo reboot"
```

## Arrakis - 10.0.1.4

1. RDP into Arrakis as follows:

```
xfreerdp +clipboard /u:dune\\patreides /p:"ebqMB7DmM81QVUqpf7XI" /v:10.0.1.4 /drive:X,sandworm/Resources/cleanup/
```

2. Open PowerShell being sure to select "Run as Administrator":

```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\cleanup-notpetya.ps1
```

3. Cleanup Quadra / 10.0.1.8

```
Invoke-Command -ComputerName 10.0.1.8 -File \\TSCLIENT\X\cleanup-notpetya.ps1 -Credential patreides
```

Enter creds when prompted:

`ebqMB7DmM81QVUqpf7XI`

Reboot arrakis and quadra

```
Invoke-Command -ComputerName 10.0.1.8 -ScriptBlock {Restart-Computer -Force} -Credential patreides
sleep 2
Restart-Computer -Force
```

## Gammu - 10.0.1.7

1. RDP into Gammu as follows:

```
xfreerdp +clipboard /u:WORKGROUP\\fherbert /p:"Whg42WbhhCE17FEzrqeJ" /v:10.0.1.7 /drive:X,sandworm/Resources/cleanup/
```

2. Open PowerShell being sure to select "Run as Administrator":

```
cd \\TSCLIENT\X
Set-Executionpolicy bypass -force
.\cleanup-gammu.ps1
```

3. Reboot gammu

```
Restart-Computer -Force
```