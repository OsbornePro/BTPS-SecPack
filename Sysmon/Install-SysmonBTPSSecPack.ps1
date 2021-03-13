# This script is meant to simplify the install of Sysmon according the BTPS Sec Pack https://www.btps-secpack.com/
$DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PrimaryDC = ($DomainObj.PdcRoleOwner).Name
$Domain = $DomainObj.Forest.Name
If ($PrimaryDC -ne "$env:COMPUTERNAME.$Domain")
{

    Throw "[x] This script is required to run on $PrimaryDC, your primary domain controller in order to push out sysmon through Group Polciy"

}  # End If


Write-Output "[*] Ensuring PowerShell uses TLSv1.2 for downloads"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


Write-Output "[*] Downloading the Sysinternals Suite tool Sysmon from Microsoft at https://download.sysinternals.com/files/Sysmon.zip"
(New-Object -TypeName System.Net.WebClient).downloadFile("https://download.sysinternals.com/files/Sysmon.zip", "$env:USERPROFILE\Downloads\Sysmon.zip")


Write-Output "[*] Unzipping the download Sysmon.zip file to your C:\Sysmon"
Expand-Archive -Path "$env:USERPROFILE\Downloads\Sysmon.zip" -Destination "C:\Sysmon\"
If (!(Test-Path -Path "C:\Sysmon\Sysmon.exe"))
{

    Throw "Failed to extract the sysmon.zip file to C:\Sysmon. Ensure you have the appropriate permissions to download to C:\"

}  # End If


Write-Output "[*] Downloading the sysmon.xml configuration file from the B.T.P.S. Security Package Github repository"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/sysmon.xml" -OutFile "C:\Sysmon\sysmon.xml"

Write-Output "[*] Downloading the sysmon.bat install file from the B.T.P.S. Security Package Github repositroy"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/sysmon.bat" -OutFile "C:\Sysmon\sysmon.bat"

$Answer1 = Read-Host -Prompt "Would you like to add the Malicious IP checker to devices in your environment as well? This provides extra checks against domains and IP addresses collected by Sysmon logged network connections. [y/N]"
If ($Answer1 -like "y*")
{

    Write-Output "[*] Downloading the Task Template for Malicious IP checker and the Script it executes"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/MaliciousIPChecker.xml" -OutFile "C:\Sysmon\MaliciousIPChecker.xml"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/MaliciousIPChecker.ps1" -OutFile "C:\Sysmon\MaliciousIPChecker.ps1"

}  # End If

$Answer2 = Read-Host -Prompt "[*] Would you like to download the Process Hash Validator as well? This script and task is used to perform extra analysis on process logs collected by Sysmon. [y/N]"
If ($Answer2 -like "y*")
{

    Write-Output "[*] Downloading Process Hash Validator task and the script that gets executed"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/HashValidator.ps1" -OutFile "C:\Sysmon\HashValidator.ps1"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/HashValidator.ps1" -OutFile "C:\Sysmon\HashValidator.ps1"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/Whitelist.csv" -OutFile "C:\Sysmon\Whitelist.csv"

}  # End If

Write-Output "[*] Turning C:\Sysmon into a Network Share for use with pushing out Sysmon logging to domain joined devices"
New-SmbShare -Name "Sysmon" -Path "C:\Sysmon" -FullAccess "$Domain\Domain Admins","Administrators" -ChangeAccess "Users"

Write-Output '[*] Disabling SMB version 1'
Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

Write-Output '[*] Enabling SMBv2 and SMBv3'
Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force


Write-Output "[*] Creating a GPO called 'Settings Sysmon' for you to configure \\$PrimaryDC\Sysmon\sysmon.bat as a startup script. I am not able to configure the rest through PowerShell unfortunately. The settings for this is easy however"
New-GPO -Name "Settings Sysmon" -Domain $Domain -Comment "Group policy object used to get sysmon installed on domain joined devices"

Write-Output "INSTRUCTIONS ON CONFIGURING SYSMON STARTUP SCRIPT IN GPO"
Write-Output "  1.) In Server Manager on $PrimaryDC, go to Tools > 'Group Policy Management'"
Write-Output "  2.) 'Group Policy Management' Window will open. Expand 'Forest: $Domain' > Expand 'Domains' > Expand '$Domain' > Expand 'Group Policy Objects' > Right click on 'Settings Sysmon' and select Edit"
Write-Output "  3.) Navigate the dropdowns from 'Computer Management' > 'Policies' > 'Windows Settings' > 'Scripts' > and Double Click 'Startup' to open the 'Startup Properties' Window"
Write-Output "  4.) With the 'Scripts' tab selected click the 'Add' button."
Write-Output "  5.) In the 'Script Name' text box enter your network share path to sysmon.bat which is most likely '\\$PrimaryDC.$Domain\Sysmon\sysmon.bat'. Leave the 'Parameters' text box blank"
Write-Output "  6.) Click OK and then click OK again. This completes our GPO for Sysmon"

Pause

Write-Host "For images and more info on how to configure Group Policy for Malicious IP Checker and Process Hash Validator visit https://btps-secpack.com/sysmon-setup"