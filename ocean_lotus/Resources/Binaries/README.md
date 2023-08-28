# Binaries.zip

## Move Unzipped Binaries into Payloads

A zip of the scenario binaries have been included [here](../Binaries/binaries.zip).
The binaries.zip can be unzipped to the expected directory location using the
following command and password `malware`:

```
# from the ocean-lotus directory

unzip Resources/Binaries/binaries.zip -d Resources/payloads
```

## Staging the Application Bundle on Victim

If the OSX.OceanLotus Application Bundle has not been staged on the target
Mac host yet, use the following commands to do so:

1. Copy the Application Bundle from Kali Linux machine to the Mac host:
    ```
    # from the ocean-lotus directory
    
    cd Resources/payloads/oceanlotus/
    scp -r -i /home/kali/.ssh/id_rsa_ocean conkylan.app ec2-user@10.90.30.22:/tmp/
    ```

1. SSH from the Kali Linux machine to the Mac host, entering the password when
prompted:
    ```
    ssh -i /home/kali/.ssh/id_rsa_ocean ec2-user@10.90.30.22
    ```

1. Using the SSH session, modify the file permissions of the Application Bundle
to be owned by `hpotter`, then copy the Application Bundle to
`/Users/hpotter/Downloads`:
    ```
    cd /tmp
    sudo chown -R hpotter /tmp/conkylan.app
    sudo cp -r /tmp/conkylan.app /Users/hpotter/Downloads
    ```

1. The Application Bundle should now be available in the Downloads folder of
`hpotter` and ready for scenario execution