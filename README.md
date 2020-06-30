# WindowsEventForwarding
Way to centralize important Security Events using WEF. 
These are files that can be used with Windows Event Forwarding to import important collected events from Domain Controllers and Domain Computers into a SQL database.
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

### REFERENCE LINKS
- https://blog.netnerds.net/2013/03/importing-windows-forwarded-events-into-sql-server-using-powershell/
- https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem
