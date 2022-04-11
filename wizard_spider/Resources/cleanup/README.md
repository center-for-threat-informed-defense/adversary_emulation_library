Upload-execute cleanup_dorthy.ps1

## Ryuk Cleanup

RDP into wizard/10.0.0.4

```
xfreerdp +clipboard /u:oz\\vfleming /p:"q27VYN8xflPcYumbLMit" /v:10.0.0.4 /drive:X,wizard_spider/Resources
```

Copy and run `cleanup-ryuk.ps1` to clear out the RyukReadMe.txt files, the executable and any leftover ryuk files

```
copy \\TSCLIENT\X\cleanup\cleanup-ryuk.ps1 C:\Users\Public\cleanup-ryuk.ps1
```

Delete the ps1 script

```
Remove-Item "cleanup-ryuk.ps1"
```

Run net use and check if the Z: drive is present indicating connection to toto \\10.0.0.8\C$.

```
net use
```

If it is, then disconnect the share.

```
net use Z: /delete
```
