# WindowsEventForwarding
This repo contains all the files needed for using Windows Event Forwarding to monitor for intruders.

## File List
- __DomainComputers.xml__ (Windows Event Forwarding Config file for Domain Computers ```wecutil cs DomainComputers.xml```)
- __DomainControllers.xml__ (Windows Event Forwarding Config file for Domain Controllers ```wecutil cs DomainControllers.xml```)
- __Import-EventsHourly.ps1__ (PowerShell script that imports collected WEF events into SQL database)
- __Query to Create MSSQ LDB Table__ (Creates the required database and table configuration for the MSSQL server database)
- __SQL-Query-Suspicious-Events.ps1__ (PowerShell script that discovers possible indicators of compromise and sends and an email alert)
- __TaskForSQLQueryEventsMonitor.xml__ (Task Scheduler import file that goes with SQL-Query-Suspicious-Events.ps1)
- __TaskImportFile.xml__ (Task Scheudler Import file that goes with Import-EventsHourly.ps)

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
  Server=https://wef.domain.com:5986/wsman/SubscriptionManager/WEC,Refresh=900 
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

#### STEP 3.)
Create Scheduled tasks
1. Place the powershell script __Import-EventsHourly.ps1__ into C:\Users\Public\Documents (_this is to match the Task Template in this repo_) or wherever you prefer to store this script. Be sure to sign in with a trusted Code Signing Certificate in your environment to prevent it from running malicious code. Modify the permissions so only administrators can modify the script.
2. Create a scheduled task that runs once an hour. You can use my template __TaskImportFile.xml__. Import this task and you should only need to define the user with Batch and Service permissions to run the script.
```powershell
# PowerShell Command to use code signing certificate
Set-AuthenticodeSignature C:\Users\Public\Documents\Import-EventsHourly.ps1 @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0]
```

#### Step 4.)
Create monitoring task that runs once a day
1. Add __SQL-Query-Suspicous-Events.ps1__ to C:\Users\Public\Documents which will match with the location of my XML template. Be sure to sign in with a trusted Code Signing Certificate in your environment to prevent it from running malicious code. Modify the permissions so only administrators can modify the script.
```powershell
# PowerShell Command to use code signing certificate
Set-AuthenticodeSignature C:\Users\Public\Documents\Import-EventsHourly.ps1 @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert)[0]
```
2. Import the task from __TaskForSQLQueryEventsMonitor.xml__ that runs once a day to execute SQL-Query-Suspicous-Events.ps1 
3. Edit the file __SQL-Query-Suspicous-Events.ps1__ so the email variables are set to match your environment. Once of the SQL querties will also need to be modified in order to add accounts that commonly receive special permissions such as accounts that are used for LDAP binds or domain controllers. Or don't use any special filtering. Whatever floats your boat. The SQL queries only return events from the last 24 hours. This is significantly faster than filtering the Windows Event log through XML.

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

When the script gets triggered it performs a search on all collected targeted events for the last 24 hours only. The results will not always mean compromise but they will definitely help to discover them when they happen. 
(Microsoft says the max limit of machines to collect events from is 2,000 to 4,000).
__REFERNCE:__ [https://support.microsoft.com/en-gb/help/4494356/best-practice-eventlog-forwarding-performance](https://support.microsoft.com/en-gb/help/4494356/best-practice-eventlog-forwarding-performance)

### REFERENCE LINKS
- https://blog.netnerds.net/2013/03/importing-windows-forwarded-events-into-sql-server-using-powershell/
- https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem
- https://support.microsoft.com/en-us/help/4494462/events-not-forwarded-if-the-collector-runs-windows-server
