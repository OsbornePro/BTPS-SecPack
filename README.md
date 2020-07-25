# WindowsEventForwarding
Way to centralize important Security Events using Windows Event Forwarding.
These are files that can be used with Windows Event Forwarding to import important collected events from Domain Controllers and Domain Computers into a SQL database.
The PowerShell script can be set up with Task Scheduler to send reports say once a day sending IT admins an email containing a table of events containing possible intrusion info.
These files were built upon the work done in the below links.

Follow the steps [HERE](https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem) to configure WinRM in your environment for Windows Event Forwarding. I suggest using WinRM over HTTPS as certificate validation is then required for communication over that port.
In order to use the __DomainComputers.xml__ and __DomainControllers.xml__ centralized event configuration in Windows Event Forwarding the below commands must be issued in Command Prompt.
```cmd
wecutil cs DomainComputers.xml
wecutil cs DomainControllers.xml
```

1. Once the above is configured use the __Query to Create MSSQL DB Table__ to build your SQL Database table. This is where events will be imported.
2. Place the powershell script Import-EventsHourly.ps1 into C:\Users\Public\Documents (_this is to match the Task Template in this repo_) or wherever you prefer to store this script. Be sure to sign in with a trusted Code Signing Certificate in your environment to prevent it from running malicious code. Modify the permissions so only administrators can modify the script.
3. Create a scheduled task that runs once an hour. You can use my template __TaskImportFile.xml__. Import this task and you should only need to define the user with Batch and Service permissions to run the script.
4. Create a task that runs once a day to execute SQL-Query-Suspicous-Events.ps1 Once run the script returns event information on the below possible indications of compromise from all those devices forwarding events. 
  -	Were any Event Logs Cleared
  -	Was a new Local or Domain User created anywhere (Excluding WDAGUtilityAccount)
  -	User added to a high privileged security group (Administrators, Domain Admins, Schema Admins, Enterprise Admins, Print Operators, Server Operators, Backup Operators)
  -	Was a user removed from a high privileged security group (Possible covering tracks)
  -	Were any new services run/created
  -	Were any accounts locked out
  -	Were any accounts unlocked
  -	Were any special privileges assigned outside the norm (Normal accounts: bbadmin, roadmin, paessler, cisco.admin, dnsdynamic, svc_git, Alertus.Service, <DomainController>$
  -	Were any replay attack attempts detected
  
When the script gets triggered it performs a search on all collected targeted events for the last 24 hours only. The results will not always mean compromise but they will definitely help to discover them when they happen. 
(Microsoft says the max limit of machines to collect events from is 2,000 to 4,000).
__REFERNCE:__ [https://support.microsoft.com/en-gb/help/4494356/best-practice-eventlog-forwarding-performance](https://support.microsoft.com/en-gb/help/4494356/best-practice-eventlog-forwarding-performance)

### REFERENCE LINKS
- https://blog.netnerds.net/2013/03/importing-windows-forwarded-events-into-sql-server-using-powershell/
- https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem
