# NOT COMPLETED YET

Write-Output "OsbornePro : The B.T.P.S. Security Package https://www.btps-secpack.com `n[*] Beginning the installation of the B.T.P.S Security Package"


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

$SecPackLocation = Read-Host -Prompt "This script is about to define the location of the home directory for the BTPS Sec Pack repository. `n`n[*]If your save location does not match the default location please enter it here to change it. `n[*]If left blank this script will automatically try to discover it. `nDEFAULT DIRECTORY NAME IS : $env:USERPROFILE\Downloads\BTPS-SecPack-master"

If (($SecPackLocation.Length -eq 0) -or (!(Test-Path -Path $SecPackLocation)))
{

    Write-Output "[*] Performing a search for the BTPS-SecPack-master home directory on the C drive."
    $SecPackLocation = (Get-ChildItem -Path C:\ -Filter "BTPS-SecPack-master" -Directory -ErrorAction SilentlyContinue -Force | Select-Object -First 1).FullName

}  # End If
Else 
{

    Write-Ouput "[*] Home Directory was found at $SecPackLocation"

}  # End Else

# The below objects build a method to query Active Directory for servers and computers
$DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$Domain = New-Object -TypeName System.DirectoryServices.DirectoryEntry
$PrimaryDC = ($DomainObj.PdcRoleOwner).Name
$DHCPServer = Read-Host -Prompt "Enter the FQDN of your Windows DHCP server. EXAMPLE: DHCPserver.domain.com"

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
    cmd /c robocopy $SecPackLocation\Sysmon C:\Sysmon *

    Write-Output "[*] Creating Malicious IP Checker task on $env:COMPUTERNAME. This task will still need to be pushed out to your environment using group policy"
    Register-ScheduledTask -Xml (Get-Content -Path "C:\Sysmon\MaliciousIPChecker.xml"| Out-String) -TaskName "Malicious IP Checker" -TaskPath "\" -User SYSTEM –Force

    Write-Output "Follow the setup instructions at https://btps-secpack.com/sysmon-setup to create the group policy that gets this on all the devices in your environment `nThis creates a new log in the event viewer that providers more detailed logging and allows you to use a task that monitors connections to your devices providing an alert whenver a blacklisted IP has been connected too"

    Pause

}  # End If
Else 
{
    
    Write-Output "[*] Sysmon will not be set up"

}  # End Else



Write-Output "=================== AUTORUNS ====================="
$AutoRunsAnswer = Read-Host -Prompt "Would you like to collect Autoruns information daily on $env:COMPUTERNAME? This is for investigating fileless malware compromises [y/N]"
If ($AutoRunsAnswer -like "y*")
{

    Set-Location -Path $SecPackLocation\AutoRunsToWinEvent
    .'\Install.ps1'

}  # End If
Else 
{

    Write-Output "[*] Autoruns set up is being skipped on $env:COMPUTERNAME."

}  # End Else



Write-Output "================= DEVICE DISCOVERY ================"
$DeviceDiscoveryAnswer = Read-Host -Prompt "Would you like to set up new device discovery alerts on $DHCPServer? This is for environments with less thatn 1000 computers. It will send you an alert whenever a never before seen device joins your network"
If ($DeviceDiscoveryAnswer -like "y*")
{

    $ScheduledTaskUser = Read-Host -Prompt "Enter the username this task should run as. This user will need 'Run as batch job' permissions as well as DHCP admin permissions `nEXAMPLE: CONTOSO\TaskSchedUser"
    cmd /c robocopy "$SecPackLocation\Device Discovery" \\$DHCPServer\C$\Users\Public\Documents *

    If ($WSMANTest -like 'True')
    {

        Invoke-Command -HideComputerName $DHCPServer -UseSSL -ScriptBlock {

            Write-Output "[*] Creating New Device Check task on $env:COMPUTERNAME. "
            New-Item -Directory -Path "C:\Users\Public\Documents\PSGetHelp" -Force -ErrorAction SilentlyContinue | Out-Null
            Move-Item -Path 'C:\Users\Public\Documents\MAC.Vendor.List.csv' -Destination 'C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv' -Force

            Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Find-NewDevices.xml"| Out-String) -TaskName "Malicious IP Checker" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later") –Force

            Write-Output "[*] The New Device Task is now set up on your DHCP server"

        }  # End Invoke-Command

    }  # End If
    Else 
    {

        Invoke-Command -HideComputerName $DHCPServer -ScriptBlock {

            Write-Output "[*] Creating New Device Check task on $env:COMPUTERNAME."
            New-Item -Directory -Path "C:\Users\Public\Documents\PSGetHelp" -Force -ErrorAction SilentlyContinue | Out-Null
            Move-Item -Path 'C:\Users\Public\Documents\MAC.Vendor.List.csv' -Destination 'C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv' -Force

            Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Find-NewDevices.xml"| Out-String) -TaskName "Malicious IP Checker" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later") –Force

            Write-Output "[*] The New Device Task is now set up on your DHCP server"
            
        }  # End Invoke-Command

    }  # End Else

}  # End If
Else 
{
    
    Write-Output "Skipping setup of Device Discovery alert on $DHCPServer"

}  # End Else

Write-Output "=========== PORT MONITORING ====================="
$PortMonitorAnswer = Read-Host -Prompt "Would you like to set up port scan monitoring? This keeps record of all connections made to a server and provides email alerts if a port scan is detected"
If ($PortMonitorAnswer -like "y*")
{

    $ScheduledTaskUser = Read-Host -Prompt "Enter the username this task should run as. This user will need 'Run as batch job' permissions as well as DHCP admin permissions `nEXAMPLE: CONTOSO\TaskSchedUser"

    If ($WSMANTest -like 'True')
    {

        ForEach ($Server in $Servers)
        {

            cmd /c robocopy "$SecPackLocation\Local Port Scan Monitor" \\$Server\C$\Users\Public\Documents *

            Invoke-Command -HideComputerName $DHCPServer -UseSSL -ScriptBlock {

                Write-Output "[*] Creating Listen Port Monitor Task on $env:COMPUTERNAME."

                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Monitor.xml"| Out-String) -TaskName "Port Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later") –Force

                Write-Output "[*] The Port Monitor Task is now set up on $env:COMPUTERNAME"


                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Scan Monitor.xml"| Out-String) -TaskName "Port Scan Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later") –Force

                Write-Output "[*] The Port Scan Monitor Task is now set up on $env:COMPUTERNAME"
                
            }  # End Invoke-Command

        }  # End ForEach

    }  # End If
    Else 
    {

        ForEach ($Server in $Servers)
        {

            cmd /c robocopy "$SecPackLocation\Local Port Scan Monitor" \\$Server\C$\Users\Public\Documents *

            Invoke-Command -HideComputerName $DHCPServer -ScriptBlock {

                Write-Output "[*] Creating Listen Port Monitor Task on $env:COMPUTERNAME."

                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Scan Monitor.xml"| Out-String) -TaskName "Port Scan Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later") –Force

                Write-Output "[*] The Port Scan Monitor Task is now set up on $env:COMPUTERNAME"


                Register-ScheduledTask -Xml (Get-Content -Path "C:\Users\Public\Documents\Port Monitor.xml"| Out-String) -TaskName "Port Monitor" -TaskPath "\" -User $ScheduledTaskUser -Password (Read-Host -Prompt "Enter the password for the user this task is going to run as. This info will be deleted from events and history later") –Force

                Write-Output "[*] The Port Monitor Task is now set up on $env:COMPUTERNAME"
                
            }  # End Invoke-Command

        }  # End ForEach

    }  # End Else

}  # End If
Else 
{

    Write-Output "Skipping the setup of port monitoring"

}  # End Else