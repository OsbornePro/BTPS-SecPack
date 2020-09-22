# The Blue Team PowerShell Security Package : OsbornePro
![OsbornePro](https://raw.githubusercontent.com/tobor88/OsbornePro-The-Blue-Team-PowerShell-Security-Package/master/WEF%20Application/WEF/WEF/wwwroot/images/osborneprologo.png)
# The B.T.P.S. Sec Pack
![The B.T.P.S. Sec Pack](https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/WEF%20Application/WEF/WEF/wwwroot/images/thebtpssecpacklogo.jpg)
This repository contains a collection of PowerShell tools that can be utilized to protect and defend an environment based on the recommendations of multiple cyber security researchers at Microsoft. 
<br>
This repo also assumes that you have referenced the Windows Event Logging Cheat Sheet for logging in your environment. Use [LOG-MD](https://www.imfsecurity.com/free) or [CIS-CAT](https://learn.cisecurity.org/benchmarks#:~:text=CIS%20Benchmarks%20are%20the%20only%20consensus-based%2C%20best-practice%20security,and%20accepted%20by%20government%2C%20business%2C%20industry%2C%20and%20academia) to ensure the recommended logging is configured.

##### NOTE: I am working on building an install script to automatically set up as much of these protections automatically as possible. Most of these scripts are email alerts and will require you to currently define the $From, $To, and $SmtpServer vairables in order to utilize the alerts and receive emails.

### What Protections Are Included?
- __Account and Password Alerts__
    - Receive alerts when an account is expiring in 2 weeks or less
    - Receive alert containing a table of all users whose passwords are expiring in two weeks or less
    - Receive an alert when a user attempts to change their password
    - Receive an alert when one account attempts to change the password of another account
    - Receive an alert when an account fails to logon to a server
    - Receive an alert when a new user account is created
    - Receive an alert when a user account is locked out
    - Receive an alert when a user account has been unlocked
- __AutoRunsToWinEvent__ [ORIGINAL](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog)
    - This basically takes creates an event log entry in event viewer containig AutoRuns hashes. I am not the author of this. I am only including this in the package as it is an important thing to keep track of
- __Device Discovery__
    - Receive an alert any time a device that has never been connected to your network before receives an IP address from one of your DHCP servers. 
- __Event Alerts__
    - Receive an alert when a DNS Zone Transfer occurs
    - Receive an alert when a new service is installed on a device that is not a Windows Defender upgrade
    - Receive an alert when an insecure LDAP bind occurs (When Bind is not LDAP over SSL)
    - Receive an alert when a user signs into a device they were not assigned 
- __Hardening Cmdlets__
    - Disable weak TLS and SSL protocols on a Client or IIS Server
    - Enable DNS over HTTPS when available
    - Fix any service paths that contain spaces in the directory names but no quotations used to prevent the execution of injected payloads
    - Uninstall PowerShell version 2 from a remote or local machine(s)
    - Remove an email reported as spam from all inboxes that receive the email
    - Rotate the Kerberos keys used in an online exchange environment
    - Enable RDP Network Level Authentication to prevent not domain computers from RDPing into a client
    - Update any available driver updates on a local or remote machine
- __Local Port Scan Monitor__
    - Receive an alert when a port scan is detected on a local device
    - Receive an alert for when a bind shell is opened and keep a record of all established connections to a device including the port and protocols used
- __WEF Application__
    - Configure Windows Event Forwarding to collect events that are clear indications of compromise
    - Receive alerts when the Centralized Windows Event Collector logs any indicators of compromise
    - View the log files inside an application to prevent needing to sign into the server to view the collected alerts
- __Windows Update Cmdlets__
    - Cmdlets that can be used to install all available windows updates
    - Cmdlet that can remove a single KB update that is not updating for whatever reason. Once removed you can use Update-Windows to reinstall the issued update.
- __Import-ScheduledTask__
    - This is a cmdlet I am going to be using when I complete the Install.ps1 file that can be used to configure all of the above. For now use the READMEs I have provided to install the desired functionalitys.
