#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
This script is used to setup the initial configuration of a Sysmon logging deployment on a Primary Domain Controller


.DESCRIPTION
Download a prebuilt Sysmon config logging file and the Sysmon executable. Set up Sysmon for deployment to devices in the domain


.PARAMETER SysmonPath
Spceify where to save the sysmon.exe file on remote devices

.PARAMETER SysmonDownloadUri
Specify where to download the Sysinternals Sysmon.zip archive file from

.PARAMETER SysmonDownloadPath
Specify where to save the Sysinternals Sysmon.zip archive file

.PARAMETER SysmonConfigUri
Specify the URL to download your Sysmon XML configuration file from

.PARAMETER UseHashValidator
Specify you want to use the hash validator in your deployment

.PARAMETER UseMaliciousIPChecker
Specify you want to use the Malicious IP Checker in your deployment

.PARAMETER VirusTotalApiKey
Enter your Virust Total API for use with the Malicious IP checker or the Hash Validator


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://btpssecpack.osbornepro.com
https://github.com/tobor88
https://github.com/osbornepro
https://www.powershellgallery.com/profiles/tobor
https://osbornepro.com
https://writeups.osbornepro.com
https://encrypit.osbornepro.com
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges


.INPUTS
None


.OUTPUTS
System.String
#>
[OutputType([System.String])]
[CmdletBinding(DefaultParameterSetName="SysmonOnly")]
param(
    [Parameter(
        Position=0,
        Mandatory=$False,
        ValueFromPipeline=$False,
        ValueFromPipelineByPropertyName=$False,
        HelpMessage="Define the parent path for saving Sysmon related files too "
    )]  # End Parameter
    [String]$SysmonPath = "C:\Program Files\Sysmon",

    [Parameter(
        Position=1,
        Mandatory=$False,
        ValueFromPipeline=$False,
        ValueFromPipelineByPropertyName=$False,
        HelpMessage="Define the locaion to download your Sysmon Zip file from or Sysmon executable from"
    )]  # End Parameter
    [ValidateScript({$_ -like "*.zip" -or $_ -like "*/sysmon.exe"})]
    [String]$SysmonDownloadUri = "https://download.sysinternals.com/files/Sysmon.zip",

    [Parameter(
        Position=2,
        Mandatory=$False,
        ValueFromPipeline=$False,
        ValueFromPipelineByPropertyName=$False,
        HelpMessage="Define the locaion to download your Sysmon Zip file from or Sysmon executable from"
    )]  # End Parameter
    [String]$SysmonDownloadPath = "$env:TEMP\Sysmon.zip",

    [Parameter(
        Position=3,
        Mandatory=$False,
        ValueFromPipeline=$False,
        ValueFromPipelineByPropertyName=$False,
        HelpMessage="Define the Raw URL location for a Sysmon configuration file"
    )]  # End Parameter
    [ValidateScript({$_ -like "*.xml"})]
    [String]$SysmonConfigUri = "https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/Sysmon/sysmon.xml",

    [Parameter(
        ParameterSetName="RequiresVirusTotal",
        Mandatory=$False
    )]  # End Parameter
    [Switch]$UseHashValidator,

    [Parameter(
        ParameterSetName="RequiresVirusTotal",
        Mandatory=$False
    )]  # End Parameter
    [Switch]$UseMaliciousIPChecker,

    [Parameter(
        ParameterSetName="RequiresVirusTotal",
        Mandatory=$True,
        ValueFromPipeline=$False,
        ValueFromPipelineByPropertyName=$False,
        HelpMessage="[H] A Virus Total API key is required to use the Malicious IP checker and/or the Hash Validator. `n[i] You can get an API key for free from https://www.virustotal.com/gui/join-us "
    )]  # End Parameter
    [String]$VirusTotalApiKey
)  # End param

BEGIN {

    Write-Verbose -Message "[v] Ensuring PowerShell uses TLSv1.2 for downloads"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    Write-Verbose -Message "[v] Ensuring directory exists for Sysmon path defined: $SysmonPath"
    New-Item -Path $SysmonPath -ItemType Directory -Force -Confirm:$False -ErrorAction SilentlyContinue | Out-Null

} PROCESS {

    Write-Verbose -Message "[v] Determinig whether the Domain Controller configuration or normal configuration is needed"
    $DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $PrimaryDC = $DomainObj.PdcRoleOwner.Name
    $Domain = $DomainObj.Forest.Name

    If ($PrimaryDC.ToLower() -eq "$env:COMPUTERNAME.$((Get-CimInstance -ClassName Win32_ComputerSystem).Domain)".ToLower()) {

        $OutFile = "$NetlogonLocalPath\Sysmon\sysmon-config.xml"
        $ConfigFileName = $OutFile.Split('\')[-1]

        Write-Verbose -Message "[v] Downloading the latest Sysinternals Suite tool Sysmon from Microsoft at https://download.sysinternals.com/files/Sysmon.zip"
        (New-Object -TypeName System.Net.WebClient).downloadFile("$SysmonDownloadUri", "$SysmonDownloadPath")
        If (!(Test-Path -Path $SysmonDownloadPath)) {

            Throw "[x] Failed to download the Sysmon.zip file. File does not exist"

        }  # End If Else

        $NetlogonLocalPath = (Get-CimInstance -Class Win32_Share -Filter "Type=0 and Name LIKE 'NETLOGON'").Path
        New-Item -Path "$NetlogonLocalPath\Sysmon" -ItemType Directory -Force -Confirm:$False -ErrorAction SilentlyContinue | Out-Null
        If (Test-Path -Path "$NetlogonLocalPath\Sysmon\sysmon.exe") {

            Write-Verbose -Message "[v] Sysmon files already exist in $NetlogonLocalPath\Sysmon"

        } Else {

            Expand-Archive -Path $SysmonDownloadPath -Destination "$NetlogonLocalPath\Sysmon" -Force
            If (!(Test-Path -Path "$NetlogonLocalPath\Sysmon\Sysmon.exe")) {

                Throw "[x] Failed to extract the sysmon.zip file to $NetlogonLocalPath\Sysmon Ensure you have the appropriate permissions to extract to $SysmonPath"

            }  # End If

        }  # End If Else

        If (Test-Path -Path "$NetlogonLocalPath\Sysmon\sysmon-config.xml") {

            Write-Verbose -Message "[v] Sysmon config file already exist in $NetlogonLocalPath\Sysmon"

        } Else {

            Write-Verbose -Message "[v] Downloading the sysmonconfig-export.xml configuration file from the OsbornePro GitHub page"
            Invoke-WebRequest -Uri $SysmonConfigUri -OutFile $OutFile | Out-Null
            If (!(Test-Path -Path $OutFile)) {

                Throw "[x] Failed to download the sysmon configuration file template to $NetlogonLocalPath\Sysmon\sysmon-config.xml"

            }  # End If

        }  # End If Else

        Write-Verbose -Message "[v] Creating the bat install file"
        $BatchContents = "if not exist `"$("$SysmonPath\$ConfigFileName".Replace($ConfigFileName, 'sysmon.exe'))`" (
mkdir `"$SysmonPath`"
copy /v /z /y `"\\$PrimaryDC\NETLOGON\Sysmon\sysmon.exe`" `"$("$SysmonPath\$ConfigFileName".Replace($ConfigFileName, 'sysmon.exe'))`"
)

sc query `"Sysmon`" | Find `"RUNNING`"
If `"%ERRORLEVEL%`" EQU `"1`" (
goto startsysmon
)
:startsysmon
net start Sysmon

If `"%ERRORLEVEL%`" EQU `"1`" (
goto installsysmon
)
:installsysmon
cd `"$SysmonPath`"
sysmon.exe -accepteula -i `"\\$PrimaryDC\NETLOGON\Sysmon\$ConfigFileName`"
"
        New-Item -Path "$NetlogonLocalPath\Sysmon" -Name "sysmon-setup.bat" -ItemType File -Value $BatchContents -Force -Confirm:$False | Out-Null

    } Else {

        Write-Verbose -Message "[v] Copying Sysmon files to local machine"
        Start-Process -FilePath "C:\Windows\System32\cmd.exe" -WorkingDirectory "C:\Windows\System32" -ArgumentList @("/c", "\\$PrimaryDC\NETLOGON\Sysmon\sysmon-setup.bat") -Wait

    }  # End If Else

    If ($UseMaliciousIPChecker.IsPresent) {

        $Answer1 = "yes"

    } Else {

        $Answer1 = Read-Host -Prompt "[?] Would you like to add the Malicious IP checker to devices in your environment as well? This provides extra checks against domains and IP addresses collected by Sysmon logged network connections. [y/N]"

    }  # End If Else

    If ($Answer1 -like "y*") {

        Write-Verbose -Message "[v] Downloading the Task Template for Malicious IP checker and the Script it executes"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/MaliciousIPChecker.xml" -OutFile "$NetlogonLocalPath\Sysmon\MaliciousIPChecker.xml"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/MaliciousIPChecker.ps1" -OutFile "$NetlogonLocalPath\Sysmon\MaliciousIPChecker.ps1"

    }  # End If


    If ($UseHashValidator.IsPresent) {

        $Answer2 = "yes"

    } Else {

        $Answer2 = Read-Host -Prompt "[?] Would you like to download the Process Hash Validator as well? This script and task is used to perform extra analysis on process logs collected by Sysmon. [y/N]"

    }  # End If Else

    If ($Answer2 -like "y*") {

        Write-Verbose -Message "[v] Downloading Process Hash Validator task and the script that gets executed"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/HashValidator.xml" -OutFile "$NetlogonLocalPath\Sysmon\HashValidator.xml"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/HashValidator.ps1" -OutFile "$NetlogonLocalPath\Sysmon\HashValidator.ps1"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/Whitelist.csv" -OutFile "$NetlogonLocalPath\Sysmon\Whitelist.csv"

        ((Get-Content -Path "$NetlogonLocalPath\Sysmon\HashValidator.ps1") -Replace "`$VirusTotalApiKey = ''","`$VirusTotalApiKey = '$VirusTotalApiKey'") | Set-Content -Path "$NetlogonLocalPath\Sysmon\HashValidator.ps1"

    }  # End If

    Write-Verbose -Message "[v] Creating a GPO called 'Settings Sysmon' for you to configure \\$PrimaryDC\Sysmon\sysmon.bat as a startup script. I am not able to configure the rest through PowerShell unfortunately. The settings for this is easy however"
    New-GPO -Name "Settings Sysmon" -Domain $Domain -Comment "Group policy object used to get sysmon installed on domain joined devices"

    $GPOInstructions = @"
    INSTRUCTIONS ON CONFIGURING SYSMON STARTUP SCRIPT IN GPO"
    1.) In Server Manager on $PrimaryDC, go to Tools > 'Group Policy Management'
    2.) 'Group Policy Management' Window will open. Expand 'Forest: $Domain' > Expand 'Domains' > Expand '$Domain' > Expand 'Group Policy Objects' > Right click on 'Settings Sysmon' and select Edit
    3.) Navigate the dropdowns from 'Computer Management' > 'Policies' > 'Windows Settings' > 'Scripts' > and Double Click 'Startup' to open the 'Startup Properties' Window
    4.) With the 'Scripts' tab selected click the 'Add' button.
    5.) In the 'Script Name' text box enter your network share path to sysmon.bat which is most likely '\\$PrimaryDC.$Domain\Sysmon\sysmon.bat'. Leave the 'Parameters' text box blank
    6.) Click OK and then click OK again. This completes our GPO for Sysmon

    For images and more info on how to configure Group Policy for Malicious IP Checker and Process Hash Validator visit https://btpssecpack.osbornepro.com/en/latest/#solo-sysmon-setup
"@

} END {

    Return $GPOInstructions

}  # End B P E
