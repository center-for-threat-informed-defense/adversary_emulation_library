$user = 'nk\zilvinasadmin';
$pword = 'Producer2!';
$securePass = ConvertTo-SecureString $pword -AsPlainText -Force;
$creds = New-Object System.Management.Automation.PSCredential $user, $securePass;
Register-PSSessionConfiguration -Name ConnectionFiltering -RunAsCredential $creds;

Invoke-Command -credential $creds -computerName localhost -scriptblock { 
  Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;

  Install-Transportagent -Name "Connection Filtering Agent" -AssemblyPath "C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\agents\Hygiene\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll" -TransportAgentFactory Microsoft.Exchange.Transport.Agent.ConnectionFiltering.ConnectionFilteringAgentFactory;

  Enable-TransportAgent -Identity "Connection Filtering Agent";

  Restart-Service MSExchangeTransport;
} -ConfigurationName ConnectionFiltering

Unregister-PSSessionConfiguration -Name ConnectionFiltering
