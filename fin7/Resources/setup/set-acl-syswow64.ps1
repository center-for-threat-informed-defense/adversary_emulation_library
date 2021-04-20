#Requires -RunAsAdministrator

$tgt_dir = "C:\Windows\SysWOW64"; # Directory to modify.

# Set ACLs on $tgt_dir to full control for everyone
$acl = Get-Acl $tgt_dir;
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","FullControl","Allow");
$acl.SetAccessRule($AccessRule);
$acl | Set-Acl "C:\Windows\SysWOW64";
if ($?) {     # if the previous command was successful, print success.
    Get-Acl $tgt_dir;
    write-host "[+] Successfully modified permissions on $tgt_dir".
    exit 0;
} else {
    write-host "[!] Error, could not modify $tgt_dir";
    exit 1;
}
