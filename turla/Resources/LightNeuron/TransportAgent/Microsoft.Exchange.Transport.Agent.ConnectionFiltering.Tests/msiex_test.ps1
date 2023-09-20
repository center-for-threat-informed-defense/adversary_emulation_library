Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

Install-Transportagent -Name "Connection Filtering Agent" -AssemblyPath "C:\Program Files\Microsoft\Exchange Server\v15\TransportRoles\agents\Hygiene\Microsoft.Exchange.Transport.Agent.ConnectionFiltering.dll" -TransportAgentFactory Microsoft.Exchange.Transport.Agent.ConnectionFiltering.ConnectionFilteringAgentFactory;

Enable-TransportAgent -Identity "Connection Filtering Agent"

Restart-Service MSExchangeTransport