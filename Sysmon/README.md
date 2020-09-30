# SYSMON CONFIGURATION
[Download Sysmon](https://download.sysinternals.com/files/Sysmon.zip)
This page is used to set up [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) logging in your environment. There are numerous benefits to this extra logging. You are able to view more information associated with events and processes than you normally would using the event viewer. I view this logging as a great extra to be doing and am attempting to encourage this logging by combining the features of this great tool with [IPNetInfo](https://www.nirsoft.net/utils/ipnetinfo.html). When used in combination with [IPNetInfo](https://www.nirsoft.net/utils/ipnetinfo.html) we will be able to analyze any IP connections a client device establishes and determine whether or not the connection has occurred to a safe or unsafe IP address. This is going to be utilized with the WEF Application in this repository as well. An event will be created and forwarded to the WEF Application which will then send an email alert thanks to the file [SQL-Query-Suspicious-Events.ps1](https://github.com/tobor88/BTPS-SecPack/blob/master/WEF%20Application/SQL-Query-Suspicous-Events.ps1)

# FILE OVERVIEW
- __Eula.txt__ This is the user license agreement for sysmon
- __sysmon.bat__ This is a start up script that will copy the sysmon.xml configuration file to a local location and use it set up your [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) configuration. This will require you to add the name of your Domain Controller. __NOTE:__ On your domain controller you will need to place the files sysmon.exe, Eula.txt, sysmon.bat, and sysmon.xml inside the network share \\\\<YourDCHere.domain.com>\\NETLOGON\\
- __sysmon.exe__ This is the [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) executable terminal application that is used to enable and start the [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) process
- __sysmon.xml__ This is the configuration file used as the starting point for this [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) configuration. Feel free to better customize this to your environment.
__REFERENCE:__ [https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)

## SETUP INSTRUCTIONS
__REFERENCE:__ [Link to Resource](https://www.syspanda.com/index.php/2017/02/28/deploying-sysmon-through-gpo/#:~:text=Launch%20your%20group%20policy%20utility%20and%20perform%20the,here%20Provide%20a%20name%20%28Sysmon%20Deployment%29%2C%20hit%20OK) <br>
The above link contains the instructions that can be followed to set up [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) in your environment.
<br> __Step 1.)__ On your domain controller you will need to place the files sysmon.exe, Eula.txt, sysmon.bat, and sysmon.xml inside the network share \\\\<YourDCHere.domain.com>\\NETLOGON\\
<br> __Step 2.)__ In the sysmon.bat script you will need to change "DomainControllerHostname" on lines 2 and 16 so it is the hostname of your Domain Controller that is hosting these files
<br> __Step 3.)__ Create a group policy item under "__Computer Configuration > Policies > Windows Settings > Scripts > Startup__" and define the Batch script location as \\yourddc.domain.com\apps\sysmon.bat and apply the policy to any devices you want this type of logging enabled on

## OTHER TOOLS IN THIS REPO
I have also included [IPNetInfo](https://www.nirsoft.net/utils/ipnetinfo.html) in this repository because this tool will be utilized to obtain the information required for analyzing IP addresses a device has connected too.
