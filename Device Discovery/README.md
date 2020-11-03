# Find-NewDevices
**Find-NewDevices** was made to discover new devices that have joined a network based on Client ID history of the DHCP Servers. This was made for System Administrators and does not take any input.

### EDIT SCRIPT
You will need to make enter a few variable values to get this to work in your environment. I have marked these lines with consecutive # characters in an attempt to easily identify where this info is needed.
- **$SmtpServer** should be your companies SMTP email server.
- **$To** is the email to send alerts too. It will prompt you if you do not define this value in the script before execution
- **$From** is the email to send alerts from. It will prompt you if you do not define this value in the script before execution

### PARAMETERS
- **$DhcpServers** parameter is an array of remote and local DHCP servers. It should include all of the servers in your environment.
- **$ComparePath** parameter is the file path that contains a list known devices. If one does not exist already it will be created automatically after running the script.
- **$MacVendorps1** parameter is the file path to the other script included in the project entitled Get-MacVendor.ps1.

### TASK SCHEDULER
I have added an XML file that can be imported to created the required task. This can __NOT__ be run as SYSTEM and will need to be run as a user with "__Run as batch job__" permissions. The Find-NewDevices.ps1 file should be configured in a task that runs at least once a day on a dhcp server. It will require a user with "Log on As Batch Job" permissions to run the task as this cmdlet issues commands on remote DHCP servers which requires network permissions. The user must also be a DHCP administrator. Use the following in the "Actions" pane of Windows Task Scheduler to run the script.
```
Program/script: powershell.exe
Add Arguments: -NoLogo -NonInteractive -WindowStyle Hidden .\Find-NewDevices.ps1
Start in (optional): C:\Users\Public\Documents
# (Or location of where you placed the script)
```

### Get-MacVendor.ps1
I wish I could remember where I obtained this cmdlet from as the maker did a great job. The cmdlet I used will require you to download a csv file containing MAC Address vendors. Be sure to do this so your results include the MAC Vendors. 

I obtained my MAC vendor list from https://macaddress.io/database-download 
To have this list fit the format required make the following changes.
```powershell
# This will replace the ":" between MAC values. If this is not removed you will not have any matches
(Get-Content -Path .\macaddress.io-db.csv).Replace(':','') | Out-File -FilePath .\MAC.Vendor.List.csv
```
Modify the headers. The 6 characters representing the vendor info should be labeled with the header "Assignment"
The company name should be labeled with the header "Organziation Name". If it makes things easier replace the first line of MAC.Vendor.List.csv with the below line
```
Assignment,isPrivate,Organization Name,Organization Address,countryCode,assignmentBlockSize,dateCreated,dateUpdated
```

As Metallica said "Nothing Else Matters"

If you need help setting this up for whatever reason feel free to contact me at rosborne@osbornepro.com and I can help with whatever part you are struggling with.
