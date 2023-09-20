# Cleanup

## Carbon Scenario

### Setup
To remove artifacts, run the [Cleanup Scripts](../cleanup/) as from the Kali hosts. You can also run the cleanup scripts on each target as described in their respective directories.

1. From the Kali Linux machine (`176.59.15.33`):
    ```
    cd /opt/day1/turla
    xfreerdp +clipboard /u:skt\\\evals_domain_admin /p:"DuapQj7k8Va8U1X27rw6" /v:10.20.10.9 /drive:X,Resources/cleanup
    ```
1. From the RDP session, open powershell in administrative mode
1. Run the cleanup commands for each implant listed below that you need to cleanup
1. Sign out of the RDP session when finished.

### EPIC
* ```
  \\tsclient\X\EPIC\epic_cleanup.ps1 -target hobgoblin -user gunter
  ```

### Carbon
* ```
    $targethosts = "hobgoblin","bannik","khabibulin"
    foreach ($targethost in $targethosts) {
        Write-Host "[+] Performing Carbon cleanup on $targethost"
        Invoke-Command -ComputerName $targethost -FilePath \\tsclient\X\Carbon\carbon_cleanup.ps1
    }
    ```

### Penquin
Additional documentation [here](../Penquin/README.md#cleanup-instructions).

* From the Kali Linux machine, SCP the Penquin cleanup script to KAGAROV:
  ```
  cd /opt/day1/turla
  scp Resources/cleanup/Penquin/cleanup_penquin.sh adalwolfa@10.20.10.23:
  ```
* Enter `Password2!` when prompted:
* Execute the cleanup script, entering `Password2!` when prompted:
  ```
  ssh adalwolfa@10.20.10.23 "sudo ./cleanup_penquin.sh && rm cleanup_penquin.sh"
  ```

## Snake Scenario

### Setup
To remove artifacts, run the [Cleanup Scripts](../cleanup/) as from the Kali hosts. You can also run the cleanup scripts on each target as described in their respective directories.

1. From the Kali Linux machine (`176.59.15.33`):
    ```
    cd /opt/day2/turla
    xfreerdp +clipboard /u:nk\\\evals_domain_admin /p:"DuapQj7k8Va8U1X27rw6" /v:10.100.30.202 /drive:X Resources/cleanup
    ```
1. From the RDP session, open powershell in administrative mode and set the execution policy
    ```
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
    ```
1. Run the cleanup commands for each implant listed below that you need to cleanup
1. Reset the execution policy
    ```
    Set-ExecutionPolicy -ExecutionPolicy Undefined -Scope CurrentUser
    ```
1. Sign out of the RDP session when finished.

### EPIC
* ```
  \\tsclient\X\EPIC\epic_cleanup.ps1 -target azuolas -user egle
  ```

### Snake
* ```
  $targethosts = "azuolas","berzas","uosis"
  \\tsclient\X\Snake\snake_cleanup.ps1 -targets $targethosts -restart -deleteInstaller
  ```

### LightNeuron
* ```
  Invoke-Command -ComputerName drebule -FileName \\tsclient\X\LightNeuron\lightneuron_cleanup.ps1
  ```
