Write-Output "[*] Ensuring install script is executing with administator privileges"
If (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {

    If ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {

        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit

    }  # End If

}  # End If


Write-Output "==============================================================================================================================="
Write-Output "|                                                     OsbornePro                                                              |"
Write-Output "|                                         The B.T.P.S. Security Package                                                       |"
Write-Output "|                      https://www.btps-secpack.com Beginning the installation of the B.T.P.S Security Package                |"
Write-Output "==============================================================================================================================="
Write-Output "[i] Suggestions and feedback are always appreciated"

$DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$DomainAttr = New-Object -TypeName System.DirectoryServices.DirectoryEntry
$DistinguishedName = $DomainAttr.distinguishedName
$Domain = $DomainObj.Forest.Name
$PrimaryDC = ($DomainObj.PdcRoleOwner).Name

If ("$env:COMPUTERNAME" -notlike $PrimaryDC.Replace(".$Domain","")) {

    Write-Output "[!] You are running this install script on a machine that is not your Primary Domain Controller. `n[!] Your primary domain controller has been detected to be $PrimaryDC. I suggest running this on that server to ensure all the commands in this install script can be run"
    $Answer = Read-Host -Prompt "Do you wish to continue the execution of this on the current machine anyway? [y/N]"

    If ($Answer -like "y*") {

        Write-Output "[*] Continuing execution of install script"

    }  # End If
    Else {

        Throw "[x] Stopping execution of the install script."

    }  # End Else

}  # End If

$BTPSHome = Read-Host -Prompt "Define the directory location you downloaded the BTPS-SecPack Git repository too. If you leave this blank it will be downloaded for you and placed in $env:USERPROFILE\Downloads\master.zip and Extracted to C:\Windows\System32\WindowsPowerShell\v1.0\BTPS-SecPack-master"
If (($BTPSHome.Length -eq 0) -or (!(Test-Path -Path $BTPSHome))) {

    Write-Output "[*] Ensuring PowerShell uses TLSv1.2 for downloads"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Write-Output "[*] Downoading the B.T.P.S Security Package."
    Invoke-WebRequest -Uri "https://github.com/tobor88/BTPS-SecPack/archive/master.zip" -OutFile "$env:USERPROFILE\Downloads\master.zip"
    Expand-Archive -Path "$env:USERPROFILE\Downloads\master.zip" -Destination "C:\Windows\System32\WindowsPowerShell\v1.0\"

    $BTPSHome = "C:\Windows\System32\WindowsPowerShell\v1.0\BTPS-SecPack-master"
    If (!(Test-Path -Path $BTPSHome)) {

        Throw "[*] Could not find the BTPS Security Package location at $BTPSHome"

    }  # End Else

}  # End If

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


    If ($ComputerName -eq $env:COMPUTERNAME) {

        Write-Verbose "Modifying access rule proteciton"

        $Acl = Get-Acl -Path "$Path"
        $Acl.SetAccessRuleProtection($True, $False)

        ForEach ($U in $Username) {

            Write-Verbose "Adding $U permissions for $Path"

            $Permission = $U, 'FullControl', 'Allow'
            $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission

            $Acl.AddAccessRule($AccessRule)

        }  # End ForEach

        Write-Verbose "Changing the owner of $Path to $Owner"

        $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount("$Owner")))
        $Acl | Set-Acl -Path "$Path"

    }  # End If
    Else {

        ForEach ($C in $ComputerName) {

            Invoke-Command -ArgumentList $Username,$Path,$Owner -HideComputerName "$C.$env:USERDNSDOMAIN" -UseSSL -Port 5986 -ScriptBlock {

                $Username = $Args[0]
                $Path = $Args[1]
                $Owner = $Args[2]

                Write-Verbose "Modifying access rule proteciton"

                $Acl = Get-Acl -Path "$Path"
                $Acl.SetAccessRuleProtection($True, $False)

                ForEach ($U in $Username) {

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

    }  # End Else

}  # End Function Set-SecureFilePermissions


Write-Output "`n`========================= EMAIL SENDING ========================="
Write-Output "[!] IMPORTANT: In order to send emails you need to authenticate to an SMTP server. This can be done using different ways.
`n`t 1 : Use a Credential File (if an attacker were to compromise the computer they can view the credentials). If you choose this option the Credential file will be saved too C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml and permissions will be set.
`n`t 2 : IP Authentication (If you are using Office365 you can configure a Connector to allow emails sent from your Public IP address to be good enough for authentication to your Exchange SMTP server)
`n`t 3 : BEST OPTION : Free SMTP2GO account (This can enable IP address authentication or use credentials that do not authenticate to anywhere else in your environment. This is the best option in my opinion"
Write-Host "Visit https://www.smtp2go.com/?s=osbornepro to create an SMTP2GO Account" -ForegroundColor Green

$CredAnswer = Read-Host -Prompt "Select one of the above methods [1/2/3]"
# CREDENTIAL FILE
If ($CredAnswer -eq "1") {

    $CredFile = Read-Host -Prompt "Where would you like the Credential file saved? `nLeave blank to use the default location C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"
    If ($CredFile.Length -eq 0) {

        $CredFile = "C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"

    }  # End If

    New-Item -Path "C:\Users\Administrator\AppData\Local\PackageManagement\" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    $Credential = Get-Credential -Message "Enter the credentials that will be used to authenticate to the SMTP server to send emails. These credentials will be saved to $CredFile. Ideally this password is strong enough that it never changes."
    $Credential | Export-CliXml -Path $CredFile

    If (!(Test-Path -Path $CredFile)) {

        Throw "[x] Credential file could not be created at $CredFile. Check your permissions and try again."

    }  # End If

    $To = Read-Host -Prompt "What is the email address that alerts should be sent TO? EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
    $From = Read-Host -Prompt "What is the email address the alerts should be sent FROM. EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
    $SmtpPort = Read-Host -Prompt "What SMTP port should be used? Use port 587 to use SSL"

}  # End If
# IP Authentication
ElseIf ($CredAnswer -eq "2") {

    $SmtpServer = Read-Host -Prompt "What is the IP Address of your SMTP server that accepts IP authentication?"
    $SmtpPort = Read-Host -Prompt "What SMTP port does your server use? EXAMPLE: 587"

}  # End ElseIf
# SMTP2GO
ElseIf ($CredAnswer -eq "3") {

    $SmtpQuestion = Read-Host -Prompt "Do you need to create and SMTP2GO account? [y/N]"
    If ($SmtpQuestion -like "y*") {

        Start-Process -FilePath "https://www.smtp2go.com/?s=osbornepro"

    }  # End If

    Write-Output "[*] Setting SMTP server to mail.smtp2go.com and using SSL on port 2525"
    $SmtpServer = 'mail.smtp2go.com'
    $SmtpPort = "2525"
    $To = Read-Host -Prompt "What is the email address that alerts should be sent to? EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
    $From = Read-Host -Prompt "Define the email address the alerts should be sent from. I usually have an email account email itself though this is not required. EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"

    $CredentialAnswer = Read-Host -Prompt "Would you like to create a credential file containing SMTP2GO credentials? I recommend this over IP authentication [y/N]"
    If ($CredentialAnswer -like "y*") {

        $CredFile = Read-Host -Prompt "Where would you like the credential file saved? `nLeave blank to use the default location C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"
        If ($CredFile.Length -eq 0) {

            $CredFile = "C:\Users\Administrator\AppData\Local\PackageManagement\btpssecpack.xml"
            New-Item -Path "C:\Users\Administrator\AppData\Local\PackageManagement\" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

            If (Test-Path -Path $CredFile) {

                Write-Output "[*] Credential file was successfully created at $CredFile"

            }  # End If

        }  # End If

        $Credential = Get-Credential -Message "Enter the SMTP2GO internal user account credentials that will be used to authenticate to the SMTP2GO server to send emails. Ideally this password is strong enough that it never needs to changes."
        $Credential | Export-CliXml -Path $CredFile

    }  # End If
    Else {

        $SmtpServer = 'mail.smtp2go.com'
        $SmtpPort = Read-Host -Prompt "What SMTP port do you want to use? Default is 2525 EXAMPLE: 2525"
        $To = Read-Host -Prompt "What is the email address that alerts should be sent TO? EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
        $From = Read-Host -Prompt "Wat is the email address the alerts should be sent FROM? EXAMPLE: $env:USERNAME@$env:USERDNSDOMAIN"
        If ($SmtpPort.Length -eq 0) {

            $SmtpPort = "2525"

        }  # End If

    }  # End Else

}  # End ElseIf

Write-Output "[*] Adding your email sending information to all alert scripts in the BTPS Security Package."

$AlertFiles = (Get-ChildItem -Path $BTPSHome -Filter "*.ps1" -Exclude "Enable-DoH.ps1","Disable-WeakSSL.ps1","ExchangeRule-DetectExternalSendersMatchingInternalNames.ps1","Fix-UnquotedServicePath.ps1","Remove-PowerShellV2.ps1","Remove-SpamEmail.ps1","Set-NetworkLevelAuthentication.ps1","Set-SecureFilePermissions.ps1","Update-Drivers.ps1","Get-MacVendor.ps1","AutorunsToWinEventLog.ps1","Install.ps1","Uninstall.ps1","Installer.ps1","Import-EventsHourly.ps1","ImportTheScheduledTasks.ps1","Remove-WindowsUpdate.ps1","Update-Windows.ps1","WEFStartupScript.ps1","Import-ScheduledTask.ps1","RemediateCompromisedOfficeAccount.ps1" -Recurse -ErrorAction SilentlyContinue -Force).FullName
ForEach ($AlertFile in $AlertFiles) {

    ((Get-Content -Path $AlertFile -Raw) -Replace "ToEmail","$To") | Set-Content -Path $AlertFile -Force
    ((Get-Content -Path $AlertFile -Raw) -Replace "FromEmail","$From") | Set-Content -Path $AlertFile -Force
    ((Get-Content -Path $AlertFile -Raw) -Replace "UseSmtpServer","$SmtpServer") | Set-Content -Path $AlertFile -Force
    ((Get-Content -Path $AlertFile -Raw) -Replace "-Port 587","-Port $SmtpPort") | Set-Content -Path $AlertFile -Force

    If (!($CredFile)) {

        (Get-Content -Path $AlertFile -Raw) -Replace "-Credential `$Credential",""

    }  # End If
    ElseIf (Test-Path -Path $CredFile) {

        Set-SecureFilePermissions -Path $CredFile -Username 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', "$Domain\Domain Admins" -Owner 'BUILTIN\Administrators' -Verbose
        (Get-Content -Path $AlertFile -Raw) -Replace "-Credential `$Credential","-Credential (Import-CliXml -Path $CredFile)"

    }  # End ElseIf

    Copy-Item -Path $AlertFiles -Destination "C:\Users\Public\Documents\"

}  # End ForEach

Write-Warning "I am not able to sign alert scripts for you because we just changed the files to include your email information."
Write-Output "[!] We are about to move the Alert scripts to other devices in your network. These should be Code Signed for Security Reasons."

$CreateCodeSigningCert = Read-Host -Prompt "Do you already have a Code Signing Certificate? [y/N]"
If ($CreateCodeSigningCert -like "N*") {

    Read-Host -Prompt "If you have not already enabled your Code Signing certificate template, do the following. Press ENTER when you are done `n`nLog into your Enterpirse Root CA Server. `nOpen 'certsrv.msc'. `nRight click on 'Certificate Templates' and select 'New' > 'Certificate Template to Issue' and select 'Code Signing' certificate. `nThis should now allow you to request a Code Signing Certificate."

    $CodeSigningCert = Get-Certificate -Template "CodeSigning" -Url "ldap:" -CertStoreLocation "Cert:\CurrentUser\My"
    Get-ChildItem | Where-Object { $_.Thumbprint -eq $CodeSigningCert.Certificate.Thumbprint } | ForEach-Object { $_.FriendlyName = "Code Signing Certificate" }
    $CSThumbprint = $CodeSigningCert.Certificate.Thumbprint

}  # End If

Write-Output "[!] Below is a list of the alert scripts that are about to be signed with your Code Signing Certificate. `n"
$CodeSignUs = "$BTPSHome\WEF Application\SQL-Query-Suspicous-Events.ps1","$BTPSHome\Local Port Scan Monitor\ListenPortMonitor.ps1","$BTPSHome\Local Port Scan Monitor\Watch-PortScan.ps1","$BTPSHome\Hardening Cmdlets\Reset-KerberosKeys.ps1","$BTPSHome\Event Alerts\DNSZoneTransferAlert.ps1","$BTPSHome\Event Alerts\Get-NewlyInstalledService.ps1","$BTPSHome\Event Alerts\NewComputerAlert.ps1","$BTPSHome\Event Alerts\Query-InsecureLDAPBinds.ps1","$BTPSHome\Event Alerts\ReviewForwardingRulesOffice.ps1","$BTPSHome\Event Alerts\UnusualUserSignInAlert.ps1","$BTPSHome\Device Discovery\Find-NewDevices.ps1","$BTPSHome\Account and Password Alerts\AccountsExpiringCheck.ps1","$BTPSHome\Account and Password Alerts\AttemptedPasswordChange.ps1","$BTPSHome\Account and Password Alerts\AttemptedPasswordReset.ps1","$BTPSHome\Account and Password Alerts\Failed.Username.and.Password.ps1","$BTPSHome\Account and Password Alerts\MonitorAdminEscalation.ps1","$BTPSHome\Account and Password Alerts\PasswordExpiryAlert.ps1","$BTPSHome\Account and Password Alerts\User.Account.Created.ps1","$BTPSHome\Account and Password Alerts\User.Account.Locked.ps1","$BTPSHome\Account and Password Alerts\User.Account.Unlocked.ps1"

Write-Output "Begining an infinite loop that will not continue Script Execution until this command returns as True : (Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCertificate)[0]"
$CertExists = (Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert)[0]
While (!($CertExists)) {

    $CertExists = (Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert)[0]
    Start-Sleep -Seconds 2

}  # End While Loop

Write-Output "[*] Using Code Signing Certifciate to sign your alert scripts"
Set-AuthenticodeSignature -FilePath $CodeSignUs @(Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert)[0]

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

BEGIN {

    $Obj = @()

}  # End BEGIN
PROCESS {

    ForEach ($Computadora in $ComputerName) {

        Try {

            Write-Verbose "[*] Attempting to connect to port 636 on $Computadora"
            $LDAPS = [ADSI]("LDAP://" + $Computadora + ":636")

        }  # End Try
        Catch {

            Write-Verbose "[x] Trouble connecting to $Computadora on port 636"
            $Error[0]

        }  # End Catch

        If ($LDAPS.Path) {

            $Protocol = 'LDAPS'

        }  # End If
        Else {

            $Protocol = 'x'

        }  # End Else

        $Obj += New-Object -TypeName PSObject -Property @{Server="$Computadora";Protocol="$Protocol"}

    }  # End ForEach

}  # End PROCESS
END {

    $Obj

}  # End END

} # End Test-LDAPS


Write-Output "[*] Determining whether or not LDAP over SSL is available"
If (!((Test-LDAPS -ComputerName $PrimaryDC).Protocol -eq 'LDAPS')) {

    Write-Warning "LDAP over SSL does not appear to be configured on $PrimaryDC. `nIf you wish to set this up I highly recommend the information at these links `nhttps://youtu.be/8rlk2xDkgLw `nhttps://social.technet.microsoft.com/wiki/contents/articles/2980.ldap-over-ssl-ldaps-certificate.aspx `nhttps://techcommunity.microsoft.com/t5/sql-server/step-by-step-guide-to-setup-ldaps-on-windows-server/ba-p/385362 `n`n[*] Continuing setup process of the BTPS Security Package."

}  # End If
Else {

    $LDAPSTest = 'True'
    Write-Output "[*] Excellent work! LDAPS connection test was passed!"

}  # End If

Register-ScheduledTask -Xml (Get-Content -Path "$BTPSHome\Event Alerts\Query-InsecureLDAPBinds.xml"| Out-String) -TaskName "Insecure LDAP Bind Discovery" -TaskPath "\" -User SYSTEM –Force
Write-Output "[*] LDAP over SSL alert task is set to inform you who performs and whenever an insecure LDAP bind is performed"

If (!(Test-WSMan -ComputerName $PrimaryDC -UseSSL -ErrorAction SilentlyContinue)) {

    Write-Warning "WinRM over SSL does not appear to be configured on $PrimaryDC `nI highly recommend using this. If you wish to set this up I suggest following my instructions at the below links.`nhttps://btpssecpack.osbornepro.com/winrm-over-https `nhttps://youtu.be/UcU2Iu9AXpM `nThis script will pause to give you time to set this up"
    Pause

}  # End If
Else {

    $WSMANTest = 'True'
    Write-Output "[*] Excellent work! WinRM over SSL is configured on $PrimaryDC"

}  # End Else

$CutOffDate = (Get-Date).AddDays(-60)
Write-Output "[*] Obtaining computer and server list based on enabled computers that have been signed into in the last 60 days: $CutOffDate"

$ComputerNames = Get-ADComputer -Properties * -Filter 'LastLogonDate -gt $CutOffDate -and ((OperatingSystem -like "Windows*Enterprise*") -or (OperatingSystem -like "Windows*Pro*")) -and (Enabled -eq "true")' | Select-Object -Property Name,DnsHostName,OperatingSystem,objectSID,DistinguishedName
$Servers = Get-ADComputer -Properties * -Filter '(LastLogonDate -gt $CutOffDate) -and (Enabled -eq "true") -and (OperatingSystem -like "*Server*")' | Select-Object -Property Name,DnsHostName,OperatingSystem,objectSID,DistinguishedName


Write-Output "=================== SYSMON ======================="
$SysmonNetworkShareRequest = Read-Host -Prompt "With your approval, this will create a network share in C:\Sysmon which will be used to install sysmon in your environment and enable the logging of blacklisted IP addresses. Is this ok to do [y/N]"

If ($SysmonNetworkShareRequest -like "y*") {

    Write-Output "Creating Sysmon share at C:\Sysmon"
    New-Item -Path "C:\Sysmon" -ItemType Directory -ErrorAction SilentlyContinue -Force | Out-Null

    Write-Output "Making C:\Sysmon a Network Share for use with group policy"
    New-SmbShare -Name "Sysmon" -Path "C:\Sysmon" -FullAccess "$Domain\Domain Admins" -Description "Network share used for Sysmon setup"

    Write-Output '[*] Disabling SMB version 1'
    Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

    Write-Output '[*] Enabling SMBv2 and SMBv3'
    Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force

    Write-Output "[*] Copying the needed files from the BTPS Sec Pack into C:\Sysmon"
    cmd /c robocopy $BTPSHome\Sysmon C:\Sysmon *

    Write-Output "[*] Creating Malicious IP Checker task on $env:COMPUTERNAME. This task will still need to be pushed out to your environment using group policy. Instructions on that can be found HERE https://btps-secpack.com/sysmon-setup"
    Register-ScheduledTask -Xml (Get-Content -Path "C:\Sysmon\MaliciousIPChecker.xml"| Out-String) -TaskName "Malicious IP Checker" -TaskPath "\" -User SYSTEM –Force

    $VTAnswer = Read-Host -Prompt "Do you have a Virus Total API Key? [y/N]"
    If ($VTAnswer -notlike "y*") {

        Start-Process -FilePath "https://www.virustotal.com/gui/join-us"
        Pause

    }  # End Else
    $VTAPIKey = Read-Host -Prompt "Paste your Virus Total API Key here: "
    ((Get-Content -Path "C:\Sysmon\HashValidator.ps1") -Replace "$VirusTotalApiKey = ''","$VirusTotalApiKey = '$VTAPIKey'") | Set-Content -Path "C:\sysmon\HashValidator.ps1"
    ((Get-Content -Path "$BTPSHome\Sysmon\HashValidator.ps1") -Replace "$VirusTotalApiKey = ''","$VirusTotalApiKey = '$VTAPIKey'") | Set-Content -Path "$BTPSHome\Sysmon\HashValidator.ps1"

    $ScheduledTaskUser = Read-Host -Prompt "Enter the username this task should run as. This user will need 'Run as batch job' permissions `nEXAMPLE: CONTOSO\TaskSchedUser"
    $SecurePassword = Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    Write-Output "[*] Creating Hash Validation Checker task on $env:COMPUTERNAME. This task will still need to be pushed out to your environment using group policy. Instructions on that can be found HERE https://btps-secpack.com/sysmon-setup"
    Register-ScheduledTask -Xml (Get-Content -Path "C:\Sysmon\HashValidator.xml"| Out-String) -TaskName "Hash Validator" -TaskPath "\" -User $ScheduledTaskUser -Password $Password –Force

    Write-Output "Follow the setup instructions at https://btpssecpack.osbornepro.com/en/latest/#solo-sysmon-setup or https://raw.githubusercontent.com/OsbornePro/Documents/main/Sysmon%20Setup-0001.pdf. Visit Page 6 to create the group policy that gets this on all the devices in your environment `nThis creates a new log in the event viewer that providers more detailed logging and allows you to use a task that monitors connections to your devices providing an alert whenver a blacklisted IP has been connected too"
    Pause

}  # End If
Else {

    Write-Output "[*] Sysmon will not be set up. If you change your mind later you can use Install-SysmonBTPSSecPack.ps1 at https://github.com/tobor88/BTPS-SecPack/blob/master/Sysmon/Install-SysmonBTPSSecPack.ps1"

}  # End Else



Write-Output "==================== AUTORUNS ======================"
If ($env:COMPUTERNAME -like $PrimaryDC) {

    Write-Output "[*] Copying AutorunsToWinEvent files into the NETLOGON directory for your domain controller."
    cmd /c  robocopy "$BTPSHome\AutoRunsToWinEvent" "C:\Windows\SYSVOL*\sysvol\$Domain\scripts" *
    $Message = "`n[*] Use Group Policy to add all the files in $BTPSHome\AutoRunsToWinEvent directory to machines in your environment.`nI demonstrate how this can be done in the 'Sysmon Setup.pdf' file at https://btps-secpack.com/sysmon-setup Page 6.`nOnce the Install.ps1 file and AutorunsToWinEvent.ps1 files are on client and server machines, you will want a task to run once that executes the Install.ps1 script.`nTask scheduler allows you to create a Task that runs one time and deletes itself after.`nExceute the .\AutoRunsToWinEvent\Install.ps1 file on machines in the environment to install this proteciton manually.`nWhen the .\AutorunsToWinEvent\Install.ps1 file is executed on a machine it does not require the task to be created as the install process was run already."
    $Message

    Write-Output "[*] Pausing Script Execution to allow you time to create the above GPO's. Information on creating Scheduled Tasks can be found here: https://btps-secpack.com/email-alerts"
    Pause

}  # End If

$AutoRunsAnswer = Read-Host -Prompt "Would you like to collect Autoruns information daily on $env:COMPUTERNAME? This is for investigating fileless malware compromises [y/N]"
If ($AutoRunsAnswer -like "y*") {

    Set-Location -Path $BTPSHome\AutoRunsToWinEvent
    ."$BTPSHome\AutoRunsToWinEvent\Install.ps1"

}  # End If
Else {

    Write-Output "[*] Autoruns set up is being skipped on $env:COMPUTERNAME."

}  # End Else



Write-Output "================= DEVICE DISCOVERY ================"
$DHCPServer = Get-ADObject -SearchBase "cn=configuration,$DistinguishedName" -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" | Select-Object -ExpandProperty "Name"
If ($DhcpServer.Length -eq 0) {

    $DhcpServer = Read-Host -Prompt "What is the FQDN of your DHCP server? EXAMPLE: dhcp.$Domain"

}  # End If

$DeviceDiscoveryAnswer = Read-Host -Prompt "Would you like to set up new device discovery alerts on $DHCPServer? This is for environments with less thatn 1000 computers. It will send you an alert whenever a never before seen device joins your network [y/N]"
If ($DeviceDiscoveryAnswer -like "y*") {

    $ScheduledTaskUser = Read-Host -Prompt "Enter the username this task should run as. This user will need 'Run as batch job' permissions as well as DHCP admin permissions `nEXAMPLE: CONTOSO\TaskSchedUser"
    cmd /c robocopy "$BTPSHome\Device Discovery" \\$DHCPServer\C$\Users\Public\Documents *

    If ($WSMANTest -like 'True') {

        Invoke-Command -HideComputerName $DHCPServer -ArgumentList $ScheduledTaskUser -UseSSL -ScriptBlock {

            $ScheduledTaskUser = $Args[0]
            Write-Output "[*] Creating New Device Check task on $env:COMPUTERNAME. "

            New-Item -ItemType Directory -Path "C:\Users\Public\Documents\PSGetHelp" -Force -ErrorAction SilentlyContinue | Out-Null
            Copy-Item -Path 'C:\Users\Public\Documents\MAC.Vendor.List.csv' -Destination 'C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv' -Force

            $SecurePassword = Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

            Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Find-NewDevices.xml"| Out-String) -TaskName "New Device Discovery" -TaskPath "\" -User $ScheduledTaskUser -Password $Password -Force
            Write-Output "[*] The 'New Device Discovery' Task is now set up on your DHCP server"

        }  # End Invoke-Command

    }  # End If
    Else {

        Invoke-Command -HideComputerName $DHCPServer -ArgumentList $ScheduledTaskUser -ScriptBlock {

            $ScheduledTaskUser = $Args[0]
            Write-Output "[*] Creating New Device Check task on $env:COMPUTERNAME. "

            New-Item -ItemType Directory -Path "C:\Users\Public\Documents\PSGetHelp" -Force -ErrorAction SilentlyContinue | Out-Null
            Copy-Item -Path 'C:\Users\Public\Documents\MAC.Vendor.List.csv' -Destination 'C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv' -Force

            $SecurePassword = Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
            $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

            Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Find-NewDevices.xml"| Out-String) -TaskName "New Device Discovery" -TaskPath "\" -User $ScheduledTaskUser -Password $Password -Force
            Write-Output "[*] The 'New Device Discovery' Task is now set up on your DHCP server"

        }  # End Invoke-Command

    }  # End Else

}  # End If
Else {

    Write-Output "Skipping setup of Device Discovery alert on $DHCPServer"

}  # End Else

Write-Output "============== PORT MONITORING ====================="
$PortMonitorAnswer = Read-Host -Prompt "Would you like to set up port scan monitoring? This keeps record of all connections made to a server and provides email alerts if a port scan is detected. `nNOTE: If you have created an email credetial file, this is the section that copies the credential file onto all available servers. If you did not make a credential file it will not be copied onto your servers. This was done to save time for you. `nANSWER [y/N]"
If ($PortMonitorAnswer -like "y*") {

    $ScheduledTaskUser = Read-Host -Prompt "Enter the username this task should run as. This user will need 'Run as batch job' permissions as well as DHCP admin permissions `nEXAMPLE: CONTOSO\TaskSchedUser"

    If ($WSMANTest -like 'True') {

        ForEach ($Server in $Servers.DnsHostName) {

            If (Test-Path -Path $CredFile) {

                $CredFileName = $CredFile.Split('\')[-1]
                $CopyDir = $CredFile.Replace("$CredFileName","")
                $PasteDir = $CopyDir.Replace("C:\","\$Server\C$\")

                cmd /c robocopy $CopyDir $PasteDir $CredFileName

            }  # End If

            cmd /c robocopy "$BTPSHome\Local Port Scan Monitor" \\$Server\C$\Users\Public\Documents *

            Invoke-Command -HideComputerName $Server -UseSSL -ArgumentList $ScheduledTaskUser -ScriptBlock {

                $SecurePassword = Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
                $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

                $ScheduledTaskUser = $Args[0]
                Write-Output "[*] Creating Listen Port Monitor Task on $env:COMPUTERNAME."
                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Monitor.xml"| Out-String) -TaskName "Port Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password $Password –Force

                Write-Output "[*] The Port Monitor Task is now set up on $env:COMPUTERNAME"


                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Scan Monitor.xml"| Out-String) -TaskName "Port Scan Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password $Password –Force
                Write-Output "[*] The Port Scan Monitor Task is now set up on $env:COMPUTERNAME"

            }  # End Invoke-Command

        }  # End ForEach

    }  # End If
    Else {

        ForEach ($Server in $Servers.DnsHostName) {

            If ($CredFile) {

                $CredFileName = $CredFile.Split('\')[-1]
                $CopyDir = $CredFile.Replace("$CredFileName","")
                $PasteDir = $CopyDir.Replace("C:\","\$Server\C$\")

                cmd /c robocopy $CopyDir $PasteDir $CredFileName

            }  # End If

            cmd /c robocopy "$BTPSHome\Local Port Scan Monitor" \\$Server\C$\Users\Public\Documents *

            Invoke-Command -HideComputerName $Server -ArgumentList $ScheduledTaskUser -ScriptBlock {

                $SecurePassword = Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later" -AsSecureString
                $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
                $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

                $ScheduledTaskUser = $Args[0]
                Write-Output "[*] Creating Listen Port Monitor Task on $env:COMPUTERNAME."

                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Scan Monitor.xml"| Out-String) -TaskName "Port Scan Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password $Password –Force
                Write-Output "[*] The Port Scan Monitor Task should now set up on $env:COMPUTERNAME"


                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Monitor.xml"| Out-String) -TaskName "Port Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password $Password –Force
                Write-Output "[*] The Port Monitor Task should now set up on $env:COMPUTERNAME"

            }  # End Invoke-Command

        }  # End ForEach

    }  # End Else

}  # End If
Else {

    Write-Output "Skipping the setup of port monitoring"

}  # End Else

Write-Output "============= ACCOUNTS AND PASSWORDS ==============="
$AccountAlertAnswer = Read-Host -Prompt "With you permission, this will create tasks on $env:COMPUTERNAME that alert on password and account changes. This also creates an alert that informs users who have a password expiring soon [y/N]"
If ($AccountAlertAnswer -like "y*") {

    $AccountAlertFiles = (Get-ChildItem -Path "$BTPSHome\Account and Password Alerts" -Filter "*.xml" -Force).FullName
    ForEach ($AccountAlertFile in $AccountAlertFiles) {

        $AccountFile = $AccountAlertFile.Split('\')[-1]
        $AccountDir = $AccountAlertFile.Replace("$AccountFile","")
        robocopy $AccountDir C:\Users\Public\Documents $AccountFile

        Register-ScheduledTask -Xml (Get-Content -Path "$AccountAlertFile"| Out-String) -TaskName $AccountFile.Replace('.xml','') -TaskPath "\" -User SYSTEM –Force
        Write-Output "[*] The $AccountFile task should now set up on $env:COMPUTERNAME"

    }  # End ForEach

}  # End If
Else {

    Write-Output "[*] Skipping alerts on changes to accounts and passwords"

}  # End Else

Write-Output "============== MISC ALERTS FOR DC ================"
$MiscAnswer = Read-Host -Prompt "With your permission, tasks wil be created that alert when a DNS zone transfer occurs and when an Unusual Sign In Occurs [y/N]"
If ($MiscAnswer -like "y*") {

    $MiscAlertFiles = (Get-ChildItem -Path "$BTPSHome\Event Alerts" -Filter *.xml -Force).FullName
    $MiscAlertFiles = $MiscAlertFiles | Where-Object { $_ -ne "$BTPSHome\Event Alerts\Query-InsecureLDAPBinds.xml" }
    $MiscAlertFiles = $MiscAlertFiles | Where-Object { $_ -ne "$BTPSHome\Event Alerts\ReviewForwardingRulesOffice.xml" }
    $MiscAlertFiles += (Get-ChildItem -Path "$BTPSHome\Event Alerts" -Filter "*.csv" -Force).FullName

    ForEach ($MiscAlertFile in $MiscAlertFiles) {

	$MiscFIle = $MiscAlertFile.Split("\")[-1]
        $MiscDir = $MiscAlertFile.Replace("$MiscFile","")
        robocopy $MiscDir C:\Users\Public\Documents $MiscFile
        robocopy $MiscDir C:\Users\Public\Documents UserComputerList.csv

        If ($MiscFile -ne $MiscAlertFiles[-1].Split("\")[-1]) {

            Register-ScheduledTask -Xml (Get-Content -Path $MiscAlertFile | Out-String) -TaskName $MiscFile.Replace(".xml","") -TaskPath "\" -User SYSTEM -Force
            Write-Output "[*] The $MiscFile task should now set up on $env:COMPUTERNAME"

        }  # End If

        Write-Output "[*] The Unusual Sign In Alert will not work until you add entries to the C:\Users\Public\Documents\UserComputerList.csv file. `n[*] Pausing execution to allow you time to do this"
        Pause

    }  # End ForEach

}  # End If



Write-Output "============== WEF Application ============="
Write-Output "[*] To install the WEF Application you will need to follow my tutorial setup guide at https://btps-secpack.com/wef-application. If you have not yet I suggest setting up WinRM over HTTPS first. https://btps-secpack.com/winrm-over-https"
Pause

Write-Output "=============== Remove PowerShell v2 =============="
$PS2Answer = Read-Host -Prompt "WINRM over SSL REQUIRERED FOR THIS : Would you like to remove the legacy version of PowerShell from the servers in your environment [y/N]"
$PS2Computer = Read-Host -Prompt "WINRM over SSL REQUIRERED FOR THIS : Would you like to remove the legacy version of PowerShell from client computers? [y/N]"

$RemovePowerShellFrom = @()
If ($PS2Answer -like "y*") {

    $RemovePowerShellFrom += $Servers.DnsHostName

}  # End If

If ($PS2Computer -like "y*") {

    $RemovePowerShellFrom += $ComputerNames.DnsHostName

}  # End If

If ($RemovePowerShellFrom.Count -gt 0) {

    ."$BTPSHome\Hardening Cmdlets\Remove-PowerShellV2"
    ForEach ($Computer in $RemovePowerShellFrom) {

        If ($Computer -NotLike "$env:COMPUTERNAME.*") {

            Remove-PowerShellV2 -ComputerName $Computer -ErrorAction Continue

        }  # End If
        Else {

            Remove-PowerShellV2 -ErrorAction Continue

        }  # End Else

    }  # End ForEach

}  # End If


Write-Output "============= ENABLE DNS OVER HTTPS =============="
$PS2Server = Read-Host -Prompt "WINRM over SSL REQUIRERED FOR THIS : Would you like to enabled DNS over HTTPS on the servers in your environment [y/N]"
$PS2Client = Read-Host -Prompt "WINRM over SSL REQUIRERED FOR THIS : Would you like to enable DNS over HTTPS on the client computers in your environment? [y/N]"

$EnableDoHOn = @()
If ($PS2Server -like "y*") {

    $EnableDoHOn += $Servers.DnsHostName

}  # End If

If ($PS2Client -like "y*") {

    $EnableDoHOn += $ComputerNames.DnsHostName

}  # End If

If ($EnableDoHOn.Count -gt 0) {

    ForEach ($Device in $EnableDoHOn) {

        If ($Device -like "$env:COMPUTERNAME.*") {

            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDOH -PropertyType DWORD -Value 2 -Force

        }  # End If
        Else {

            If ($Device -notlike "*.$Domain") {

                $Device = "$Device.$Domain"

            }  # End If

            Invoke-Command -HideComputerName $Device -UseSSL -ScriptBlock {

                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDOH -PropertyType DWORD -Value 2 -Force

            }  # End Invoke-Command

        }  # End Else

    }  # End ForEach

}  # End If

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTXnIrOig0s8tCZsLSJGzaeUp
# geCgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
# BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
# BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMx
# MDUwMzA3MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMw
# EQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEt
# MCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMw
# MQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0g
# RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYusw
# ZLiBCGzDBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz
# 6ojcnqOvK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am
# +GZHY23ecSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1g
# O7GyQ5HYpDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQW
# OlDxSq7neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB
# 0lL7AgMBAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
# BjAdBgNVHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqF
# BxBnKLbv9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDov
# L2NybC5nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0g
# ADAzMDEGCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9z
# aXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyI
# BslQj6Zz91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwl
# TxFWMMS2RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKo
# cyQetawiDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1
# KrKQ0U11GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkK
# rqeKM+2xLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDABMIIFIzCC
# BAugAwIBAgIIXIhNoAmmSAYwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQK
# ExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFk
# ZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMjAxMTE1MjMyMDI5WhcNMjExMTA0
# MTkzNjM2WjBlMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xGTAXBgNV
# BAcTEENvbG9yYWRvIFNwcmluZ3MxEzARBgNVBAoTCk9zYm9ybmVQcm8xEzARBgNV
# BAMTCk9zYm9ybmVQcm8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
# V6Cvuf47D4iFITUSNj0ucZk+BfmrRG7XVOOiY9o7qJgaAN88SBSY45rpZtGnEVAY
# Avj6coNuAqLa8k7+Im72TkMpoLAK0FZtrg6PTfJgi2pFWP+UrTaorLZnG3oIhzNG
# Bt5oqBEy+BsVoUfA8/aFey3FedKuD1CeTKrghedqvGB+wGefMyT/+jaC99ezqGqs
# SoXXCBeH6wJahstM5WAddUOylTkTEfyfsqWfMsgWbVn3VokIqpL6rE6YCtNROkZq
# fCLZ7MJb5hQEl191qYc5VlMKuWlQWGrgVvEIE/8lgJAMwVPDwLNcFnB+zyKb+ULu
# rWG3gGaKUk1Z5fK6YQ+BAgMBAAGjggGFMIIBgTAMBgNVHRMBAf8EAjAAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1BgNVHR8ELjAsMCqgKKAm
# hiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUtNi5jcmwwXQYDVR0gBFYw
# VDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2VydGlmaWNh
# dGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATB2BggrBgEFBQcB
# AQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29tLzBABggr
# BgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0
# b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0gzCiM9f7bLPwtCyAzjAd
# BgNVHQ4EFgQUkWYB7pDl3xX+PlMK1XO7rUHjbrwwDQYJKoZIhvcNAQELBQADggEB
# AFSsN3fgaGGCi6m8GuaIrJayKZeEpeIK1VHJyoa33eFUY+0vHaASnH3J/jVHW4BF
# U3bgFR/H/4B0XbYPlB1f4TYrYh0Ig9goYHK30LiWf+qXaX3WY9mOV3rM6Q/JfPpf
# x55uU9T4yeY8g3KyA7Y7PmH+ZRgcQqDOZ5IAwKgknYoH25mCZwoZ7z/oJESAstPL
# vImVrSkCPHKQxZy/tdM9liOYB5R2o/EgOD5OH3B/GzwmyFG3CqrqI2L4btQKKhm+
# CPrue5oXv2theaUOd+IYJW9LA3gvP/zVQhlOQ/IbDRt7BibQp0uWjYaMAOaEKxZN
# IksPKEJ8AxAHIvr+3P8R17UxggJjMIICXwIBATCBwTCBtDELMAkGA1UEBhMCVVMx
# EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT
# EUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRk
# eS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIIXIhNoAmmSAYwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FH2byPpczeryFydkfJ05Qir5bBJyMA0GCSqGSIb3DQEBAQUABIIBAFw+cQqOcRxo
# cI/R55hfMiyh6pF4BTxMFwbh7d+TsyP1x42nEmDZsMiQpJZQjlbUPvoVutA0H2S9
# lY5yMHVvNzpL40guV3vJ9EADcZm7Kh2fUkjpot6UL8QJZ65GiKQuxEGZgSQAwAel
# sH1f3x4eEhSiySgMyEqanJk+bx1IKk57I1XQrdzf4+a6g2gPCijDRpq1zzh/nhP6
# akQcWewnsVmAe9qT9AjOau44yf/9RW1ECAs8EytgG1AobsJM4yBgEIYoGT3QlbEq
# +DWgeDOTR/nOOUlnxCP4wS7S1UdjGqH8vGZK6y5F7BKB0bvKCzSPlFq6mMj1bgvp
# G5tuAuGCU3E=
# SIG # End signature block
