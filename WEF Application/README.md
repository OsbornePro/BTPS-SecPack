# WindowsEventForwarding
This repo contains all the files needed for using Windows Event Forwarding to monitor for intruders. 
This repo also assumes that you have referenced the Windows Event Logging Cheat Sheet for logging in your environment. Use [LOG-MD](https://www.imfsecurity.com/free) or [CIS-CAT](https://learn.cisecurity.org/benchmarks#:~:text=CIS%20Benchmarks%20are%20the%20only%20consensus-based%2C%20best-practice%20security,and%20accepted%20by%20government%2C%20business%2C%20industry%2C%20and%20academia) to ensure the recommended logging is configured.

__STARTUP SCRIPT NOTE:__ Windows Event Forwarding can be tricky. I have computers in the same OU with the exact same settings and configuations applied with some servers forwarding events and other servers not forwarding events. To compensate I have the below lines added to a startup script which was done to ensure the correct permissions are applied and the WinRM service is available for communication.
```powershell
Write-Verbose "Giving NETWORK SERVICE permissions to the Security log for WEF"
cmd /c 'wevtutil sl Security /ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)'

Write-Verbose "Add NETWORK SERVICE to event log readers group for WEF"
Add-LocalGroupMember -Group "Event Log Readers" -Member "NETWORK SERVICE" -ErrorAction SilentlyContinue | Out-Null

Write-Verbose "Ensuring WinRM service is available for WEF communication"
$EventInfo = Get-WinEvent -LogName 'Microsoft-Windows-Forwarding/Operational' -MaxEvents 1
If ($EventInfo.LevelDisplayName -ne "Information")
{

    cmd /c 'sc config WinRM type= own'

}  # End If
```

## File List
- __DomainComputers.xml__ (Windows Event Forwarding Config file for Domain Computers ```wecutil cs DomainComputers.xml```)
- __DomainControllers.xml__ (Windows Event Forwarding Config file for Domain Controllers ```wecutil cs DomainControllers.xml```)
- __Import-EventsHourly.ps1__ (PowerShell script that imports collected WEF events into SQL database)
- __ImportTheScheduledTasks.ps1__ (This is an optional script that can be used to import the task scheduler xml files, simultaneously creating the needed scheduled tasks on the Windows Event Log Collector centralized Server)
- __Query to Create MSSQ LDB Table__ (Creates the required database and table configuration for the MSSQL server database)
- __SQL-Query-Suspicious-Events.ps1__ (PowerShell script that discovers possible indicators of compromise and sends and an email alert)
- __TaskForSQLQueryEventsMonitor.xml__ (Task Scheduler import file that goes with SQL-Query-Suspicious-Events.ps1)
- __TaskImportFile.xml__ (Task Scheudler Import file that goes with Import-EventsHourly.ps)
- __WEFStartupScript.ps1__ (This should be the startup script on all devices sending events to the source WEF collector)

## PREREQUISITES
- Download and Install [SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver15)
- WinRM (Preferably WinRM over HTTPS) needs to be configured in your environment Follow the steps [HERE](https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem) to configure WinRM in your environment for Windows Event Forwarding.
  ```powershell
  # Some WinRM Commands to know that may be helpful
  Enable-PSRemoting -Force # Enables firewall rules for WinRM
  winrm qc -q # Qucik config for WinRM 5985
  winrm enum winrm/config/listener # Enumerate cert thumbprint used on different winrm ports
  winrm delete winrm/config/listener?Address=*+Transport=HTTPS # Delete winrm certificate and stop listener on 5986. This allows new cert to be attached to port
  winrm create winrm/config/listener?Address=*+Transport=HTTPS # Creates a WinRM listener on 5986 using any available certificate
  # The below command defines a certificate to use on port 5986. Certificate Template needed is a Web Server certificate from Windows PKI
  New-WSManInstance -ResourceUri WinRM/Config/Listener -SelectorSet @{Address = "*"; Transport = "HTTPS"} -ValueSet @{Hostname = FqdnRequiredHere.domain.com; CertificateThumbprint = $Thumbprint }
  ```
- Group Policy setting "__Computer Configuration__ > __Policies__ > __Adminsitrative Templates__ > __Windows Components__ > __Event Forwarding__ > __Configure Target Subscription Manager__" needs to be set to 
  - __WinRM__ (Port 5985): NOTE: The refresh interval is not required. I have it set to the default value (15 minutes) in the configs below
  ```
  Server=http://wef.domain.com:5985/wsman/SubscriptionManager/WEC,Refresh=900 
  ```
  __OR__
  - __WinRM over HTTPS__ (Port 5986): In my environment I added 3 entries for this. One without a CA certificate, one with spaces after every 2 numbers, and one without spaces in the root CA's certificate thumbprint
  ```
  # Examples
  Server=https://wef.domain.com:5986/wsman/SubscriptionManager/WEC,Refresh=900,IssuerCA=ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
  Server=https://wef.domain.com:5986/wsman/SubscriptionManager/WEC,Refresh=900,IssuerCA=ffffffffffffffffffffffffffffffffffffffff 
  Server=https://wef.domain.com:5986/wsman/SubscriptionManager/WEC,Refresh=900 
  ```
  - Group Policy Setting "__Computer Configuration__ > __Policies__ > __Adminsitrative Templates__ > __Windows Components__ > __Event Log Service__ > __Security__ > __Change Log Access__" needs to be set to the value of the property "__ChannelAccess__" after issuing the command ```wevtutil gl security```
  - Group Policy Setting "__Computer Configuration__ > __Policies__ > __Adminsitrative Templates__ > __Windows Components__ > __Event Log Service__ > __Security__ > __Change Log Access (Legacy)__" needs to be set to the value of the property "__ChannelAccess__" after issuing the command ```wevtutil gl security```
<br>

### Certificates requirements
A server authentication certificate has to be installed on the Event Collector computer in the Personal store of the Local machine. The subject of this certificate has to match the FQDN of the collector. <br>
<br>
A client authentication certificate has to be installed on the Event Source computers in the Personal store of the Local machine. The subject of this certificate has to match the FQDN of the computer. <br>
<br>
If the client certificate has been issued by a different Certification Authority than the one of the Event Collector then those Root and Intermediate certificates needs to be installed on the Event Collector as well. <br>
<br>
If the client certificate was issued by an Intermediate certification authority and the collector is running Windows 2012 or later you will have to configure the following registry key: __HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\ClientAuthTrustMode (DWORD) = 2__ <br>
```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" -Name "ClientAuthTrustMode" -Value 2 -Force
```
<br>
Verify that both the server and client are able to successfully check revocation status on all certificates. Use of the certutil command can assist in troubleshooting any errors.<br>
<br>
### Setup the listener on the Event collector
Set the certificate authentication with the following command:
```powershell
cmd /c 'winrm set winrm/config/service/auth @{Certificate="true"}'
```
A WinRM HTTPS listener with the server authentication certificate thumb print should exist on the event collector computer. This can be verified with the following command:
```powershell
winrm e winrm/config/listener
```
If you do not see the HTTPS listener, or if the HTTPS listener's thumb print is not same as the thumb print of the server authentication certificate on collector computer, then you can delete that listener and create a new one with the correct thumb print. To delete the https listener, use the following command:
```powershell
winrm delete winrm/config/Listener?Address=*+Transport=HTTPS
```
To create a new listener, use the following command:
```powershell
winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname="<FQDN of the collector>";CertificateThumbprint="<Thumb print of the server authentication certificate>"}
```
<br>
Create the certificate mapping using a certificate that is present in the machine’s “Trusted Root Certification Authorities” or “Intermediate Certification Authorities”.
```powershell
winrm create winrm/config/service/certmapping?Issuer=<Thumbprint of the issuing CA certificate>+Subject=*+URI=* @{UserName="<LocalAdministrator>";Password="<password>"} -remote:localhost
```
<br>
From a client test the listener and the certificate mapping with the following command:
```powershell
winrm g winrm/config -r:https://<Event Collector FQDN>:5986 -a:certificate -certificate:"<Thumbprint of the client authentication certificate>"
```
<br>

This should return the WinRM configuration of the Event collector. Do not move past this step if the configuration is not displayed.
<br>
## SET UP USING THESE FILES
#### STEP 1.)
In order to use the __DomainComputers.xml__ and __DomainControllers.xml__ config files in Windows Event Forwarding the below commands must be issued in an Administrator Command Prompt.
```cmd
wecutil cs DomainComputers.xml
wecutil cs DomainControllers.xml
```

#### STEP 2.)
Create the SQL database schema and table.
1. Open SSMS (SQL Server Management Studio)
2. Click "Execute New Query" in the top ribbon.
3. Copy and paste the contents of __Query to Create MSSQL DB Table__ into the query and click "Execute" This builds your SQL Database table where events will be imported.

#### (STEP 3 and STEP 4's tasks can be created by executing the ImportTheScheduledTasks.ps1 script after downloading this git)
<br>

#### STEP 3.)
Create Scheduled Task to Import Events into SQL Database
1. Place the powershell script __Import-EventsHourly.ps1__ into C:\Users\Public\Documents (_this is to match the Task Template in this repo_) or wherever you prefer to store this script. Be sure to sign it with a trusted Code Signing Certificate in your environment _(Import Code Signing Cert Info __"Trusted Publishers"__ store in certmgr.msc)_ to prevent it from running malicious code. Modify the permissions so only administrators can modify the script. Have this run every hour on minute 55. This leaves time for the events to get imported into the SQL database. Then on the hour, have the next task run.
1. Create a scheduled task that runs once an hour. You can use my template __TaskImportFile.xml__. Import this task and you should only need to define the user with Batch and Service permissions to run the script.

```powershell
# PowerShell Command to use code signing certificate
Set-AuthenticodeSignature C:\Users\Public\Documents\Import-EventsHourly.ps1 @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0]
```

#### Step 4.)
Create Monitoring and Alert Task
1. Add __SQL-Query-Suspicous-Events.ps1__ to C:\Users\Public\Documents which will match with the location of my XML template. Be sure to sign in with a trusted Code Signing Certificate _(Import Code Signing Cert Info __"Trusted Publishers"__ store in certmgr.msc)_ in your environment to prevent it from running malicious code. Modify the permissions so only administrators can modify the script. Have this task run on the hour.
```powershell
# PowerShell Command to use code signing certificate
Set-AuthenticodeSignature C:\Users\Public\Documents\Import-EventsHourly.ps1 @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0]
```
2. Import the task from __TaskForSQLQueryEventsMonitor.xml__ that runs once a day to execute SQL-Query-Suspicous-Events.ps1 
3. Edit the file __SQL-Query-Suspicous-Events.ps1__ so the email variables are set to match your environment. Once of the SQL querties will also need to be modified in order to add accounts that commonly receive special permissions such as accounts that are used for LDAP binds or domain controllers. Or don't use any special filtering. Whatever floats your boat. The SQL queries only return events from the last hour. This is significantly faster than filtering the Windows Event log through XML which also will eventually delete logs to make room for newer logs.

Once run, the script returns event information on the below possible indications of compromise from all those devices forwarding events. 
  -	Were any Event Logs Cleared
  -	Was a new Local or Domain User created anywhere (Excluding WDAGUtilityAccount)
  -	User added to a high privileged security group (Administrators, Domain Admins, Schema Admins, Enterprise Admins, Print Operators, Server Operators, Backup Operators)
  -	Was a user removed from a high privileged security group (Possible covering tracks)
  -	Were any new services run/created
  -	Were any accounts locked out
  -	Were any accounts unlocked
  -	Were any special privileges assigned outside the norm (Normal accounts: admin, dnsdynamic, <DomainController>$
  -	Were any replay attack attempts detected

#### Step 5.) 
To ensure the correct permissions are set on the Windows Event Log Source Collector issue the below commands (on the Windows Event Forwarding Collection Server)
```cmd
netsh http delete urlacl url=http://+:5985/wsman/ 
netsh http add urlacl url=http://+:5985/wsman/ sddl=D:(A;;GX;;;S-1-5-80-569256582-2953403351-2909559716-1301513147-412116970)(A;;GX;;;S-1-5-80-4059739203-877974739-1245631912-527174227-2996563517)
netsh http delete urlacl url=https://+:5986/wsman/
netsh http add urlacl url=https://+:5986/wsman/ sddl=D:(A;;GX;;;S-1-5-80-569256582-2953403351-2909559716-1301513147-412116970)(A;;GX;;;S-1-5-80-4059739203-877974739-1245631912-527174227-2996563517)
```

#### IMAGE OF AN EMAILED ALERT
![Email Alert Image](https://raw.githubusercontent.com/tobor88/WindowsEventForwarding/master/Email%20Alert%20Image.png)
![Another Alert Image](https://raw.githubusercontent.com/tobor88/WindowsEventForwarding/master/Alert2.png)

When the script gets triggered it performs a search on all collected targeted events for the last 1 hour and 5 minutes only. You can change this in the task and SQL Query script. The results will not always mean compromise but they will definitely help to discover them when they happen.
(Microsoft says the max limit of machines to collect events from is 2,000 to 4,000).
__REFERNCE:__ [https://support.microsoft.com/en-gb/help/4494356/best-practice-eventlog-forwarding-performance](https://support.microsoft.com/en-gb/help/4494356/best-practice-eventlog-forwarding-performance)

### REFERENCE LINKS
- https://blog.netnerds.net/2013/03/importing-windows-forwarded-events-into-sql-server-using-powershell/
- https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem
- https://support.microsoft.com/en-us/help/4494462/events-not-forwarded-if-the-collector-runs-windows-server
- https://serverfault.com/questions/769282/windows-event-log-forwarding-permission
