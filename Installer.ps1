# NOT COMPLETED YET

Function Test-Admin {
    [CmdletBinding()]
        param()  # End param

    Write-Verbose "Verifying permissions"
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If ($IsAdmin)
    {
    
        Write-Verbose "Permissions verified, continuing execution"
    
    }  # End If
    Else
    {
    
        Throw "[x] Insufficient permissions detected. Run this cmdlet in an adminsitrative prompt."

    }  # End Else

}  # End Function Test-Admin

Write-Output "[*] Ensuring install script is executing with administator privileges"
Test-Admin 

Write-Output "OsbornePro : The B.T.P.S. Security Package https://www.btps-secpack.com `n[*] Beginning the installation of the B.T.P.S Security Package`n`n"

$DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$Domain = New-Object -TypeName System.DirectoryServices.DirectoryEntry
$PrimaryDC = ($DomainObj.PdcRoleOwner).Name

If ($env:COMPUTERNAME -ne $PrimaryDC)
{

    Write-Output "[!] You are running this install script on a machine that is not your Primary Domain Controller. `n[!] Your primary domain controller has been detected to be $PrimaryDC. I suggest running this on that server to ensure all the commands in this install script can be run"
    $Answer = Read-Host -Prompt "Do you wish to continue the execution of this on the current machine anyway? [y/N]"

    If ($Answer -like "y*")
    {

        Write-Output "[*] Continuing execution of install script"

    }  # End If
    Else 
    {

        Throw "[x] Stopping execution of the install script."

    }  # End Else

}  # End If

$BTPSHome = Read-Host -Prompt "This script is about to define the location of the home directory for the BTPS Sec Pack repository. `n`n[*]If your save location does not match the default location please enter it here to change it. `n[*]If left blank this script will automatically try to discover it. `nDEFAULT DIRECTORY NAME IS : $env:USERPROFILE\Downloads\BTPS-SecPack-master"
If (($BTPSHome.Length -eq 0) -or (!(Test-Path -Path $BTPSHome)))
{

    Write-Output "[*] Performing a search for the BTPS-SecPack-master home directory on the C drive."
    $BTPSHome = (Get-ChildItem -Path C:\ -Filter "BTPS-SecPack-master" -Directory -ErrorAction SilentlyContinue -Force | Select-Object -First 1).FullName

}  # End If

If (!(Test-Path -Path $BTPSHome))
{

    Throw "[*] Could not find the BTPS Security Package location at $BTPSHome"

}  # End Else


Write-Output "========================= EMAIL SENDING ========================="
Write-Output "[!] IMPORTANT: In order to send emails you need to authenticated to an SMTP server. This can be done using a credential file however, if an attacker were to compromise the computer they can view the credentials. If you choose to take this route the crednetials will be saved to a local administrator directory in an attempt to only allow privileged users to read the file. Credential file will be saved too C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"
Write-Output "`tIf you are using Office365 I have had success in using the Public IP address of an Office365 Exchange SMTP server. This works as long as the emails are coming from on site and you have a Connector configured. The authentiation occuring here is the Public IP Address for your workplace has configured a 'Connector' allowing emails to be sent to internal addresses without passing credentials."
Write-Output "`nAnother option is to sign up for a free SMTP2GO account and enable IP address authentication. This will allow you to send emails using their SMTP servers without saving credentials to any of the machines. You can also use credentials with SMTP2GO that ONLY authenticate to the SMTP2GO servers meaning the password you configure with them will not allow access to any of your devices."

$CredAnswer = Read-Host -Prompt "Knowing the above information, would you like to create a credential file anyway containing authentication to your company email servers? Answer No if you do not want to use domain credentials to authenticate to the SMTP server [y/N]"
If ($CredAnswer -like "y*")
{

    $CredFile = Read-Host -Prompt "Where would you like the credential file saved? `nThe default location is C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"
    If ($CredFile.Length -eq 0)
    {

        $CredFile = "C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"

    }  # End If

    $Credential = Get-Credential -Message "Enter the credentials that will be used to authenticate to the SMTP server to send emails. These credentials will be saved to $CredFile. Ideally this password is strong enough that it never changes."
    $Credential | Export-CliXml -Path $CredFile

    If (!(Test-Path -Path $CredFile))
    {

        Throw "[x] Credential file could not be created at $CredFile. Check your permissions and try again."

    }  # End If

    $To = Read-Host -Prompt "What is the email address that alerts should be sent to? EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
    $From = Read-Host -Prompt "Define the email address the alerts should be sent from. I usually have an email account email itself though this is not required. EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
    $SmtpPort = Read-Host -Prompt "What SMTP port should be used? Use port 587 to use SSL"

}  # End If
Else 
{

    $SmtpQuestion = Read-Host -Prompt "Are you going to use SMTP2GO? [y/N]`nNOTE: If you answer NO then you will be prompted for an IP address of your Office365 Exchange server. If you are unsure of the IP address, contact their support through the Office365 Admin Center at https://admin.microsoft.com/ and ask for the IP address of an SMTP server you use."
    If ($SmtpQuestion -like "y*")
    {

        Start-Process -FilePath https://www.smtp2go.com/

        Write-Output "[*] Setting SMTP server to mail.smtp2go.com and port to 2525"
        $SmtpServer = 'mail.smtp2go.com'
        $SmtpPort = 2525
        $To = Read-Host -Prompt "What is the email address that alerts should be sent to? EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
        $From = Read-Host -Prompt "Define the email address the alerts should be sent from. I usually have an email account email itself though this is not required. EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"

        $CredentialAnswer = Read-Host -Prompt "Would you like to create a credential file containing SMTP2GO credentials? [y/N]"
        If ($CredentialAnswer -like "y*")
        {

            $CredFile = Read-Host -Prompt "Where would you like the credential file saved? `nThe default location is C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"
            If ($CredFile.Length -eq 0)
            {

                $CredFile = "C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"

            }  # End If
    
            $Credential = Get-Credential -Message "Enter the credentials that will be used to authenticate to the SMTP2GO server to send emails. These credentials will be $CredFile. Ideally this password is strong enough that it never changes."
            $Credential | Export-CliXml -Path $CredFile

        }  # End If
        Else 
        {

            $SmtpServer = Read-Host -Prompt "What is the IP address of your SMTP server?"
            $SmtpPort = Read-Host -Prompt "What SMTP port do you want to use? If you want to use SSL when sending the email, set this value to be port 587."
            $To = Read-Host -Prompt "What is the email address that alerts should be sent to? EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
            $From = Read-Host -Prompt "Define the email address the alerts should be sent from. I usually have an email account email itself though this is not required. EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"

        }  # End Else

    }  # End If

}  # End Else

If (Test-Path -Path $CredFile)
{

    Write-Output "[*] Credential file was successfully created at $CredFile"

}  # End If

Write-Output "[*] Adding the defined email sending information to all alert scripts in the BTPS Security Package."

$AlertFiles = (Get-ChildItem -Path $BTPSHome -Filter "*.ps1" -Exclude "Enable-DoH.ps1","Disable-WeakSSL.ps1","ExchangeRule-DetectExternalSendersMatchingInternalNames.ps1","Fix-UnquotedServicePath.ps1","Remove-PowerShellV2.ps1","Remove-SpamEmail.ps1","Set-NetworkLevelAuthentication.ps1","Set-SecureFilePermissions.ps1","Update-Drivers.ps1","Get-MacVendor.ps1","AutorunsToWinEventLog.ps1","Install.ps1","Uninstall.ps1","Installer.ps1","Import-EventsHourly.ps1","ImportTheScheduledTasks.ps1","Remove-WindowsUpdate.ps1","Update-Windows.ps1","WEFStartupScript.ps1","Import-ScheduledTask.ps1","RemediateCompromisedOfficeAccount.ps1" -Recurse -ErrorAction SilentlyContinue -Force).FullName
ForEach ($AlertFile in $AlertFiles)
{

    (Get-Content -Path $AlertFile -Raw) -Replace "To","$To"
    (Get-Content -Path $AlertFile -Raw) -Replace "From","$From"
    (Get-Content -Path $AlertFile -Raw) -Replace "SmtpServer","$SmtpServer"
    If (!($CredFile))
    {

        (Get-Content -Path $AlertFile -Raw) -Replace "-Credential `$Credential",""

    }  # End If
    ElseIf (Test-Path -Path $CredFile)
    {

        (Get-Content -Path $AlertFile -Raw) -Replace "-Credential `$Credential",""

    }  # End ElseIf

}  # End ForEach


Function Test-LDAPS {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$True,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True,
                HelpMessage='Enter the hostname or ip address of a domain controller to test LDAPS on. Separate multiple values with a comma')]
            [Alias('cn','Computer','Server')]
	        [String[]]$ComputerName
        )  # End param

BEGIN
{

    $Obj = @()

}  # End BEGIN
PROCESS
{

    ForEach ($Computadora in $ComputerName)
    {

        Try
        {

            Write-Verbose "[*] Attempting to connect to port 636 on $Computadora"
            $LDAPS = [ADSI]("LDAP://" + $Computadora + ":636")

        }  # End Try
        Catch
        {

            Write-Verbose "[x] Trouble connecting to $Computadora on port 636"
            $Error[0]

        }  # End Catch

        If ($LDAPS.Path)
        {

            $Protocol = 'LDAPS'

        }  # End If
        Else
        {

            $Protocol = 'x'

        }  # End Else

        $Obj += New-Object -TypeName PSObject -Property @{Server="$Computadora";Protocol="$Protocol"}
	
    }  # End ForEach

}  # End PROCESS
END
{

    $Obj

}  # End END

} # End Test-LDAPS

Function Set-SecureFilePermissions {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Add a user or list of users who should have permisssions to an NTFS file`n[E] EXAMPLE: 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc'")]  # End Parameter
            [Alias('User')]
            [String[]]$Username,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="`n[H] Define the path to the NTFS item you want to modify the entire permissions on `n[E] EXAMPLE: C:\Temp\file.txt")]  # End Parameter
            [String[]]$Path,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]
            [String]$Owner = 'BUILTIN\Administrators',

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Alias('cn')]
            [String[]]$ComputerName = $env:COMPUTERNAME)  # End param


    ForEach ($C in $ComputerName)
    {

        Invoke-Command -ArgumentList $Username,$Path,$Owner -HideComputerName "$C.$env:USERDNSDOMAIN" -UseSSL -Port 5986 -ScriptBlock {

            $Username = $Args[0]
            $Path = $Args[1]
            $Owner = $Args[2]

            Write-Verbose "Modifying access rule proteciton"

            $Acl = Get-Acl -Path "$Path"
            $Acl.SetAccessRuleProtection($True, $False)

            ForEach ($U in $Username) 
            {

                Write-Verbose "Adding $U permissions for $Path"

                $Permission = $U, 'FullControl', 'Allow'
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission

                $Acl.AddAccessRule($AccessRule)

            }  # End ForEach

            Write-Verbose "Changing the owner of $Path to $Owner"

            $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount("$Owner")))
            $Acl | Set-Acl -Path "$Path"

        }  # End Invoke-Command

    }  # End ForEach

}  # End Function Set-SecureFilePermissions


Write-Output "[*] Determining whether or not LDAP over SSL is available"
If (!((Test-LDAPS -ComputerName $PrimaryDC).Protocol -eq 'LDAPS'))
{

    Write-Warning "LDAP over SSL does not appear to be configured on $PrimaryDC. `nIf you wish to set this up I highly recommend the information at these links `nhttps://social.technet.microsoft.com/wiki/contents/articles/2980.ldap-over-ssl-ldaps-certificate.aspx `nhttps://techcommunity.microsoft.com/t5/sql-server/step-by-step-guide-to-setup-ldaps-on-windows-server/ba-p/385362 `n`n[*] Continuing setup process of the BTPS Security Package."


}  # End If
Else 
{

    $LDAPSTest = 'True'

}  # End If


If (!(Test-WSMan -ComputerName $PrimaryDC -UseSSL -ErrorAction SilentlyContinue))
{

    Write-Warning "WinRM over SSL does not appear to be configured on $PrimaryDC `nI recommend using this. If you wish to set this up I suggest following my instructions at the below link.`nhttps://btps-secpack.com/winrm-over-https `nThis script will pause to give you time to set this up"

    Pause

}  # End If
Else 
{

    $WSMANTest = 'True'
    Write-Output "[*] WinRM over SSL is configured on $PrimaryDC"

}  # End Else

$CutOffDate = (Get-Date).AddDays(-60)
Write-Output "[*] Obtaining computer and server list based on enabled computers that have been signed into in the last 60 days: $CutOffDate"

$ComputerNames = Get-ADComputer -Properties * -Filter 'LastLogonDate -gt $CutOffDate -and ((OperatingSystem -like "*Windows *Enterprise") -or (OperatingSystem -like "*Windows *Pro*")) -and (Enabled -eq "true")' | Select-Object -Property Name,DnsHostName,OperatingSystem,objectSID,DistinguishedName
$Servers = Get-ADComputer -Properties * -Filter 'LastLogonDate -gt (Get-Date.AddDays(-60) -and OperatingSystem -like "*Server*" -and Enabled -eq "true"' | Select-Object -Property Name,DnsHostName,OperatingSystem,objectSID,DistinguishedName



Write-Output "=================== SYSMON ======================="
$SysmonNetworkShareRequest = Read-Host -Prompt "With your approval this will create a network share in C:\Sysmon which will be used to install sysmon in your environment and enable the logging of blacklisted IP addresses. Is this ok to do [y/N]" 

If ($SysmonNetworkShareRequest -like "y*")
{

    Write-Output "Creating Sysmon share at C:\Sysmon"
    New-Item -Path "C:\Sysmon" -ItemType Directory -ErrorAction SilentlyContinue -Force | Out-Null 

    Write-Output "Making C:\Sysmon a Network Share for use with group policy"
    New-SmbShare -Name "Sysmon" -Path "C:\Sysmon" -ContinuouslyAvailable -FullAccess "$Domain\Domain Admins" -ChangeAccess "$Domain\Domain Admins" -ReadAccess "$Domain\Authenticated Users","$Domain\Domain Users" -Description "Network share used for Sysmon setup"

    Write-Output "[*] Copying the needed files from the BTPS Sec Pack into C:\Sysmon"
    cmd /c robocopy $BTPSHome\Sysmon C:\Sysmon *

    Write-Output "[*] Creating Malicious IP Checker task on $env:COMPUTERNAME. This task will still need to be pushed out to your environment using group policy"
    Register-ScheduledTask -Xml (Get-Content -Path "C:\Sysmon\MaliciousIPChecker.xml"| Out-String) -TaskName "Malicious IP Checker" -TaskPath "\" -User SYSTEM –Force

    Write-Output "Follow the setup instructions at https://btps-secpack.com/sysmon-setup to create the group policy that gets this on all the devices in your environment `nThis creates a new log in the event viewer that providers more detailed logging and allows you to use a task that monitors connections to your devices providing an alert whenver a blacklisted IP has been connected too"

    Pause

}  # End If
Else 
{
    
    Write-Output "[*] Sysmon will not be set up"

}  # End Else



Write-Output "==================== AUTORUNS ======================"
If ($env:COMPUTERNAME -like $PrimaryDC)
{

    Write-Output "[*] Copying AutorunsToWinEvent files into the NETLOGON directory for your domain controller. `n[*] Use Group Policy to add these files to machines in your environment. Once the Install.ps1 file and AutorunsToWinEvent.ps1 files are on client and server machines, you will want a task to run once that executes the Install.ps1 script. Task scheduler allows you to create a Task that runs one time and deletes itself after. Exceute the .AutoRunsToWinEvent\Install.ps1 file on machines in the environment to install this proteciton. If the .\Install.ps1 file is executed on a machine it does not require the task to be created as the install process was run already."
    cmd /c  robocopy "$BTPSHome\AutoRunsToWinEvent" "C:\Windows\SYSVOL*\sysvol\$Domain\scripts" *

    Write-Output "[*] Pausing Script Execution to allow you time to create the GPO containing the task as well as the files out to machines in the environment. Information on creating Scheduled Tasks can be found here: https://btps-secpack.com/email-alerts"
    Pause 

}  # End If

$AutoRunsAnswer = Read-Host -Prompt "Would you like to collect Autoruns information daily on $env:COMPUTERNAME? This is for investigating fileless malware compromises [y/N]"
If ($AutoRunsAnswer -like "y*")
{

    Set-Location -Path $BTPSHome\AutoRunsToWinEvent
    .'\Install.ps1'

}  # End If
Else 
{

    Write-Output "[*] Autoruns set up is being skipped on $env:COMPUTERNAME."

}  # End Else



Write-Output "================= DEVICE DISCOVERY ================"
$DHCPServer = Read-Host -Prompt "Enter the FQDN of your Windows DHCP server. EXAMPLE: DHCPserver.domain.com"

$DeviceDiscoveryAnswer = Read-Host -Prompt "Would you like to set up new device discovery alerts on $DHCPServer? This is for environments with less thatn 1000 computers. It will send you an alert whenever a never before seen device joins your network"
If ($DeviceDiscoveryAnswer -like "y*")
{

    $ScheduledTaskUser = Read-Host -Prompt "Enter the username this task should run as. This user will need 'Run as batch job' permissions as well as DHCP admin permissions `nEXAMPLE: CONTOSO\TaskSchedUser"
    cmd /c robocopy "$BTPSHome\Device Discovery" \\$DHCPServer\C$\Users\Public\Documents *

    If ($WSMANTest -like 'True')
    {

        Invoke-Command -HideComputerName $DHCPServer -ArgumentList $ScheduledTaskUser -UseSSL -ScriptBlock {

            $ScheduledTaskUser = $Args[0]
            Write-Output "[*] Creating New Device Check task on $env:COMPUTERNAME. "

            New-Item -Directory -Path "C:\Users\Public\Documents\PSGetHelp" -Force -ErrorAction SilentlyContinue | Out-Null
            Move-Item -Path 'C:\Users\Public\Documents\MAC.Vendor.List.csv' -Destination 'C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv' -Force


            Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Find-NewDevices.xml"| Out-String) -TaskName "Malicious IP Checker" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString | ConvertFrom-SecureString -AsPlainText) –Force
            Write-Output "[*] The New Device Task is now set up on your DHCP server"

        }  # End Invoke-Command

    }  # End If
    Else 
    {

        Invoke-Command -HideComputerName $DHCPServer -ScriptBlock {

            Write-Output "[*] Creating New Device Check task on $env:COMPUTERNAME."
            New-Item -Directory -Path "C:\Users\Public\Documents\PSGetHelp" -Force -ErrorAction SilentlyContinue | Out-Null
            Move-Item -Path 'C:\Users\Public\Documents\MAC.Vendor.List.csv' -Destination 'C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv' -Force

            Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Find-NewDevices.xml"| Out-String) -TaskName "Malicious IP Checker" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString | ConvertFrom-SecureString -AsPlainText) –Force

            Write-Output "[*] The New Device Task is now set up on your DHCP server"
            
        }  # End Invoke-Command

    }  # End Else

}  # End If
Else 
{
    
    Write-Output "Skipping setup of Device Discovery alert on $DHCPServer"

}  # End Else

Write-Output "============== PORT MONITORING ====================="
$PortMonitorAnswer = Read-Host -Prompt "Would you like to set up port scan monitoring? This keeps record of all connections made to a server and provides email alerts if a port scan is detected. NOTE: If you have created an email credetial file, this is the section that copies the credential file onto all available servers. If you did not make a crednetial file it will not be copied onto your servers. This was done to save time for you."
If ($PortMonitorAnswer -like "y*")
{

    $ScheduledTaskUser = Read-Host -Prompt "Enter the username this task should run as. This user will need 'Run as batch job' permissions as well as DHCP admin permissions `nEXAMPLE: CONTOSO\TaskSchedUser"

    If ($WSMANTest -like 'True')
    {

        ForEach ($Server in $Servers)
        {

            If ($CredFile)
            {

                $CredFileName = $CredFile.Split('\')[-1]
                $CopyDir = $CredFile.Replace("$RemoveString","")
                $PasteDir = $CopyDir.Replace("C:\","\\$Server\C$\")

                cmd /c robocopy $CopyDir $PasteDir $CredFileName

            }  # End If

            cmd /c robocopy "$BTPSHome\Local Port Scan Monitor" \\$Server\C$\Users\Public\Documents *

            Invoke-Command -HideComputerName $Server -UseSSL -ScriptBlock {

                Write-Output "[*] Creating Listen Port Monitor Task on $env:COMPUTERNAME."
                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Monitor.xml"| Out-String) -TaskName "Port Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString | ConvertFrom-SecureString -AsPlainText) –Force

                Write-Output "[*] The Port Monitor Task is now set up on $env:COMPUTERNAME"


                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Scan Monitor.xml"| Out-String) -TaskName "Port Scan Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString | ConvertFrom-SecureString -AsPlainText) –Force
                Write-Output "[*] The Port Scan Monitor Task is now set up on $env:COMPUTERNAME"
                
            }  # End Invoke-Command

        }  # End ForEach

    }  # End If
    Else 
    {

        ForEach ($Server in $Servers)
        {

            If ($CredFile)
            {

                $CredFileName = $CredFile.Split('\')[-1]
                $CopyDir = $CredFile.Replace("$RemoveString","")
                $PasteDir = $CopyDir.Replace("C:\","\\$Server\C$\")

                cmd /c robocopy $CopyDir $PasteDir $CredFileName

            }  # End If
            
            cmd /c robocopy "$BTPSHome\Local Port Scan Monitor" \\$Server\C$\Users\Public\Documents *

            Invoke-Command -HideComputerName $Server -ArgumentList $ScheduledTaskUser -ScriptBlock {

                $ScheduledTaskUser = $Args[0]
                Write-Output "[*] Creating Listen Port Monitor Task on $env:COMPUTERNAME."

                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Scan Monitor.xml"| Out-String) -TaskName "Port Scan Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString | ConvertFrom-SecureString -AsPlainText) –Force
                Write-Output "[*] The Port Scan Monitor Task should now set up on $env:COMPUTERNAME"


                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Monitor.xml"| Out-String) -TaskName "Port Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString | ConvertFrom-SecureString -AsPlainText) –Force
                Write-Output "[*] The Port Monitor Task should now set up on $env:COMPUTERNAME"
                
            }  # End Invoke-Command

        }  # End ForEach

    }  # End Else

}  # End If
Else 
{

    Write-Output "Skipping the setup of port monitoring"

}  # End Else

Write-Output "============= ACCOUNTS AND PASSWORDS ==============="
$AccountAlertAnswer = Read-Host -Prompt "With you permission this will create tasks on $env:COMPUTERNAME that alert on password and account changes. This also creates an alert that informs users who have a password expiring soon [y/N]"
If ($AccountAlertAnswer -like "y*")
{

    $AccountAlertFiles = (Get-ChildItem -Path "$BTPSHome\Accounts and Password Alerts" -Filter "*.xml" -Force).FullName
    ForEach ($AccountAlertFile in $AccountAlertFiles)
    {

        $AccountFile = $AccountAlertFile.Split('\')[-1]
        $AccountDir = $AccountAlertFile.Replace("$AccountFile","")
        robocopy $AccountDir C:\Users\Public\Documents $AccountFile

        Register-ScheduledTask -Xml (Get-Content -Path "$AccountAlertFile"| Out-String) -TaskName $AccountFile.Replace('.xml','') -TaskPath "\" -User SYSTEM –Force
        Write-Output "[*] The $AccountFile task should now set up on $env:COMPUTERNAME"

    }  # End ForEach

}  # End If
Else 
{

    Write-Output "[*] Skipping alerts on changes to accounts and passwords"

}  # End Else

Write-Output "============== MISC ALERTS FOR DC ================"
$MiscAnswer = Read-Host -Prompt "With your permission, tasks wil be created that alert when a DNS zone transfer occurs, insecure LDAP Binds occur or an Unusual Sign In Occurs [y/N]"
If ($MiscAnswer -like "y*")
{
 
    $MiscAlertFiles = (Get-ChildItem -Path "$BTPSHome\Event Alerts" -Filter "*.xml" -Force).FullName
    $MiscAlertFiles = $MiscAlertFiles | Where-Object { $_ –notlike "*ReviewForwardingRulesOffice.xml" }
    $MiscAlertFiles += (Get-ChildItem -Path "$BTPSHome\Event Alerts" -Filter "*.csv" -Force).FullName

    ForEach ($MiscAlertFile in $MiscAlertFiles)
    {

        $MiscFile = $MiscAlertFile.Split('\')[-1]
        $MiscDir = $MiscAlertFile.Replace("$MiscFile","")
        robocopy $MiscDir C:\Users\Public\Documents $MiscFile
        robocopy $MiscDir C:\Users\Public\Documents UserComputerList.csv

        If ($MiscFile -notlike $MiscAlertFiles[-1])
        {
        
            Register-ScheduledTask -Xml (Get-Content -Path "$MiscAlertFile"| Out-String) -TaskName $MiscFile.Replace('.xml','') -TaskPath "\" -User SYSTEM –Force
            Write-Output "[*] The $MiscFile task should now set up on $env:COMPUTERNAME"

        }  # End If

        Write-Output "[*] The Unusual Sign In Alert will not work until you add entries to the C:\Users\Public\Documents\UserComputerList.csv file. Pausing execution to allow you time to do this"

        Pause

    }  # End ForEach

}  # End If

Write-Output "============== WEF Application ============="
Write-Output "[*] To install the WEF Application you will need to follow my tutorial setup guide at https://btps-secpack.com/wef-application "
Pause 