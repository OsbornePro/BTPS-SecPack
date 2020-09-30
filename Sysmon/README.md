# SYSMON CONFIGURATION
[Download Sysmon](https://download.sysinternals.com/files/Sysmon.zip)
This page is used to set up [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) logging in your environment. There are numerous benefits to this extra logging. You are able to view more information associated with events and processes than you normally would using the event viewer. I view this logging as a great extra to be doing and am attempting to encourage this logging. When used in combination with [MaliciousIPChecker.ps1](https://github.com/tobor88/BTPS-SecPack/blob/master/Sysmon/MaliciousIPChecker.ps1) we will be able to analyze any IP connections a client device establishes and determine whether or not the connection has occurred to a safe or unsafe IP address. This is going to be utilized with the WEF Application in this repository as well. An event will be created and forwarded to the WEF Application which will then send an email alert thanks to the file [SQL-Query-Suspicious-Events.ps1](https://github.com/tobor88/BTPS-SecPack/blob/master/WEF%20Application/SQL-Query-Suspicous-Events.ps1)

# FILE OVERVIEW
- __Eula.txt__ This is the user license agreement for sysmon
- __sysmon.bat__ This is a start up script that will copy the sysmon.xml configuration file to a local location and use it set up your [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) configuration. This will require you to add the name of your Domain Controller. __NOTE:__ On your domain controller you will need to place the files sysmon.exe, Eula.txt, sysmon.bat, and sysmon.xml inside the network share \\\\<YourDCHere.domain.com>\\NETLOGON\\
- __sysmon.exe__ This is the [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) executable terminal application that is used to enable and start the [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) process
- __sysmon.xml__ This is the configuration file used as the starting point for this [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) configuration. Feel free to better customize this to your environment.
- __MaliciousIPChecker.ps1__ This is the PowerShell script that is used to execute against a list a sysmon connections from the last hour. 
__REFERENCE:__ [https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)

## SETUP INSTRUCTIONS
__REFERENCE:__ [Link to Resource](https://www.syspanda.com/index.php/2017/02/28/deploying-sysmon-through-gpo/#:~:text=Launch%20your%20group%20policy%20utility%20and%20perform%20the,here%20Provide%20a%20name%20%28Sysmon%20Deployment%29%2C%20hit%20OK) <br>
The above link contains the instructions that can be followed to set up [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) in your environment.
<br> __Step 1.)__ On your domain controller you will need to place the files sysmon.exe, Eula.txt, sysmon.bat, and sysmon.xml inside the network share \\\\<YourDCHere.domain.com>\\NETLOGON\\
<br> __Step 2.)__ In the sysmon.bat script you will need to change "DomainControllerHostname" on lines 2 and 16 so it is the hostname of your Domain Controller that is hosting these files
<br> __Step 3.)__ Create a group policy item under "__Computer Configuration > Policies > Windows Settings > Scripts > Startup__" and define the Batch script location as \\yourddc.domain.com\apps\sysmon.bat and apply the policy to any devices you want this type of logging enabled on
<br> __Step 4.)__ Sign up for an account at [HERE To get an API Key](https://user.whoisxmlapi.com/). Then create a scheduled task to push out through Group Policy that executes the PowerShell Script [MaliciousIPChecker.ps1](https://github.com/tobor88/BTPS-SecPack/blob/master/Sysmon/MaliciousIPChecker.ps1) once an hour. You will need to add your API key to the script on line one for the value $APIKey. You can choose a difference DNS server if you like. By Default I have Cloudflare's 1.1.1.1 server configured as the DNS server to keep resolutions anonymous.

## How Does MaliciousIPCheckerWork?
This works by pulling any network connections made from the Sysmon logs. It then extracts the IP addresses that were connected too and saves the results to C:\Windows\Temp\SysmonEvents.txt. To save to this location your task will need to be running as someone with "__Administrator__" permissions as well as "__Run as batch job__" permissions. I recommend of course using a Code Signing Certificate to sign this script while it is running as a Task to prevent an attacker from trying to use it for Privilege Escalation. With the task running once an hour and the last hour of sysmon logs being checked you should be able to check the majority of IP address connections if not all of them. These IP addresses are then resolved using a Reverse DNS lookup before using your API key to perform a WhoIs lookup and return the domain information. 
#### I still need to do more work to get the event created and sent too the WEF Applcation. This is currently not doing anything other than obtaining information

### SIGN SCRIPT WITH CERT
```powershell
# Sign the script with your code signing cert using the below command. Request one if needed at certmgr.msc
Set-AuthenticodeSignature C:\Path\To\MaliciousIPChecker.ps1 @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCertificate)[0]
```
