## Generate Self Signed Certificate

```
# Create self signed certificate
$cert = New-SelfSignedCertificate -DnsName www.bargaining-active.com -Subject "CN=Bargaining active,E=pashulke67@gmail.com" -Type CodeSigningCert -CertStoreLocation Cert:\CurrentUser\My\

# Set certificate password
$CertPassword = ConvertTo-SecureString -String "attackevals" -Force -AsPlainText

# Export certificate to disk
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath self-signed-cert.pfx -Password $CertPassword

# Sign executable
$cert = Get-PfxCertificate -FilePath .\self-signed-cert.pfx
Set-AuthenticodeSignature -FilePath <path/to/exe/script> -Certificate $cert
```