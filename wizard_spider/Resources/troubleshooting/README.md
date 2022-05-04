# Troubleshooting

## I can't RDP into domain hosts!

DNS is most likely screwed up - we need to fix it.

RDP into the host as local admin, for example:

```
xfreerdp +clipboard /u:WORKGROUP\\fbaum /p:"t3EY8hDubtAPXgAODmCj" /v:10.0.0.7
```

or for sandworm:

```
xfreerdp +clipboard /u:WORKGROUP\\fherbert /p:"Whg42WbhhCE17FEzrqeJ" /v:10.0.1.7
```

Hit the Windows key, type "Ethernet settings", click the app.

Click "Change Adapter Options"

Select Ethernet 3

Right-click Ethernet 3, select "Properties", then "Internet Protocol Version 4" then "Properties".

Select "Use the following DNS server addresses"

Type your domain controller IP address in the first field.

For Wizard Spider, that is 10.0.0.4.

Select okay; you'll likely be disconnected.

Ask Eric / infrastructure for a reboot through Azure, otherwise reboot manually.

Give it a few minutes and then try to login as intended.

## Logging into Kali dev boxes from a Windows Computer

1) Open the `Remote Desktop Connection` application.
    - Note: Click the `Show Options` if this is your first time and continue with the steps below, if you had a saved RDP profile skip to step 4.
2) Type the IP of the Kali Computer. For example, `192.168.0.4`
3) Type the User name you were given with the domain you are joining. For example, `dungeon\myuser`
    - Note: At this point you can make other settings changes like reducing the display resolution, color depth to reduce bandwidth, or change local resources.
4) Check the box `Allow me to save credentials` (important!) and click Save or Save As... 
5) Click connect and a windows login prompt will appear, type your password and you should be in!
    - Note: Once you login succesfully you will also have the ability to check "Always ask for credentials".
