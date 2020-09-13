﻿<#
.SYNOPSIS
This cmdlet is used to verify functions are being executed with administrative privileges.


.DESCRIPTION
Tests to make sure a commands executer is a member of the administrators group. If they are not the script stops execution before failing its tasks.


.EXAMPLE
Test-Admin
# This examples test to ensure the current user is a member of the local Administrators group.


.NOTES
Author: Rob Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String


.OUTPUTS
None
    
    
.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
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


<#
.SYNOPSIS
This cmdlet is used to create the Firewall Log files inside the directory specified in the $Path parameter. 
The default path value is determined by the CIS Benchmarks. If the files are not manually created the log files will not hold any information.


.DESCRIPTION
This cmdlet tests to make sure the files do not already exist before creating them. 
The default value creates the appropriately named firewall log files in C:\Windows\System32\logfiles\Firewall directory.


.PARAMETER Path
Defines the Directory Path where the firewall log files should be saved and logging too


.EXAMPLE
New-FirewallLogFile
# This example creates a firewall log file domainfw.log, domainfw.log.old, privatefw.log, privatefw.log.old, publicfw.log, and publicfw.log.old in the directory C:\Windows\System32\logfiles\firewall directory and gives permissions to SYSTEM, Administrators, Network Configuration Operators, and MpsSvc.

.EXAMPLE
New-FirewallLogFile -Path C:\Windows\Temp
# This example creates a firewall log file domainfw.log, domainfw.log.old, privatefw.log, privatefw.log.old, publicfw.log, and publicfw.log.old in the directory C:\Windows\Temp directory and gives permissions to SYSTEM, Administrators, Network Configuration Operators, and MpsSvc.


.NOTES
Author: Rob Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String


.OUTPUTS
None
    
    
.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function New-FirewallLogFile
{
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="[H] Define the directory location to save firewall logs too. `n[E] EXAMPLE: C:\Windows\System32\LogFiles\Firewall"
            )]  # End Parameter
            [String]$Path = "C:\Windows\System32\LogFiles\Firewall"
        )  # End param

BEGIN 
{

    Test-Admin

    $FirewallLogFiles = "$Path\domainfw.log","$Path\domainfw.log.old","$Path\privatefw.log","$Path\privatefw.log.old","$Path\publicfw.log","$Path\publicfw.log.old","$Path"

    New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

}  # End BEGIN
PROCESS
{
  
  Write-Output "[*] Creating firewall log files in $Path"
  New-Item -Path $FirewallLogFiles -Type File -Force -ErrorAction SilentlyContinue | Out-Null


  Write-Output "[*] Setting permissions on the log files created"
  $Acl = Get-Acl -Path $FirewallLogFiles
  $Acl.SetAccessRuleProtection($True, $False)


  $PermittedUsers = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc', 'USAV\sour.pell')
  ForEach ($User in $PermittedUsers) 
  {

    $Permission = $User, 'FullControl', 'Allow'

    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission

    $Acl.AddAccessRule($AccessRule)

  }  # End ForEach

}  # End PROCESS
END
{

    $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount('BUILTIN\Administrators')))
    $Acl | Set-Acl -Path $FirewallLogFiles

}  # End END

}  # End Function New-FirewallLog


<#
.SYNOPSIS
This cmdlet is used to enabled Firewall logging and defines the file and path to write log information too


.DESCRIPTION
Enables the Windows Firewall and sets the log file path that firewall logs should be written to. Enabls logging of traffic blocked by the Windows Firewall.
This will assign Domain Firewall logs to domainfw.log, Pricate firewall logs to privatefw.log, and Public firewall logs to publicfw.log


.PARAMETER Path
Define the location to save the .log firewall files. This location will be where your firewall logs are sent too. The file naming is based on the CIS Benchmarks.


.EXAMPLE
Enable-FirewallLogging -FilePath C:\Windows\System32\LogFiles\Firewall
This example enables the windows firewall, enables logging of traffic blocked by the firewall and defines the file to send the log information too according to the CIS Benchmarks.


.NOTES
Author: Rob Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Enable-FirewallLogging {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="[H] Define the full path and file name to where the firewall log files will be. `n[E] EXAMPLE: C:\Windows\System32\LogFiles\Firewall")]
            [ValidateNotNullOrEmpty()]
            [String]$Path
        )  # End param


    Test-Admin

    Write-Verbose "Enabling Windows Firewall"
    Set-NetFirewallProfile -Enabled True

    $Result = Get-NetFirewallProfile | Select-Object -Property Name,Enabled

    ForEach ($Re in $Result)
    {

        If ((($Re).Enabled) -eq 'True')
        {

            Write-Output "[*] Firewall has been enabled"
            
            "[*] FW PROFILE : " + $Re.Name
            "[*] LOG ENABLE : " + $Re.Enabled

        }   # End If
        ElseIf (($Re.Enabled) -eq 'False')
        {

            Write-Output "[x] Firewall is disabled. This may because of group policy settings. Your current settings are below"
            
            "[*] FW PROFILE : " + $Re.Name
            "[*] LOG ENABLE : " + $Re.Enabled

        }  # End ElseIf

    }  # End ForEach


    Write-Verbose "Enable logging for blocked connections"

    Set-NetFirewallProfile -Name Domain -LogAllowed True -LogBlocked True -LogFileName "$Path\domainfw.log"
    Set-NetFirewallProfile -Name Private -LogAllowed True -LogBlocked True -LogFileName "$Path\privatefw.log"
    Set-NetFirewallProfile -Name Public -LogAllowed False -LogBlocked True -LogFileName "$Path\publicfw.log"

    $Results = Get-NetFirewallProfile | Select-Object -Property Name,LogAllowed,LogBlocked,LogFileName

    ForEach ($R in $Results)
    {

        If ((($R).LogBlocked) -eq 'True')
        {

            Write-Output "[*] Firewall logging of blocked connections has been enabled"

            "[*] FW PROFILE: " + $R.Name
            "[*] LOG RULE  : " + $R.LogBlocked

        }   # End If
        ElseIf (($R.LogBlocked) -eq 'False')
        {

            Write-Output "[x] Firewall logging of blocked connectiosn was NOT enabled"

            "[*] FW PROFILE: " + $R.Name
            "[*] LOG RULE  : " + $R.Logblocked

        }  # End ElseIf

    }  # End ForEach

}  # End Function 


<#
.SYNOPSIS
This cmdlet is used to block an IP address using the Windows Firewall.


.DESCRIPTION
Creates a firewall rule that blocks inbound and outbound connections to a defined IP Address.
This creates a singular firewall rule for each IP address provided for easy management and more customizable results when used in combination with other functions.


.PARAMETER IPAddress
Specify an single value or array of IP addresses that you wish to create a firewall rule for blocking inbound and outbound connections


.EXAMPLE
Block-IPAddress -IPAddress '10.10.10.10','10.10.11.11'
This example creates a firewall rule tha blocks inbound and outbound connections to IP addresses 10.10.10.10 and 10.10.11.11.

.EXAMPLE
$IP = '192.168.0.1'; $IP | Block-IPAddress
This example creates a firewall rule that blocks inbound and outbound connections to IP addresses 192.168.0.1.


.NOTES
Author: Rob Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.Int32


.OUTPUTS
None


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Block-IPAddress {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="[H] Define an IP address or multiple IP addresses separating multiple values with a comma. `n[E] EXAMPLE: '10.10.10.10','10.12.12.12'"            
            )]  # End Parameter
            [ValidateScript({$Ipaddress | ForEach-Object {[System.Net.IPAddress]$_}})]
            [String[]]$IPAddress
        )  # End param

    
    ForEach ($IP in $IPAddress)
    {

        Write-Verbose "Obtaining updated list of all the firewall rule names"
        $FirewallRule = New-Object -ComObject HNetCfg.FwPolicy2
        $FwRuleNames = $FirewallRule.Rules | Select-Object -Property "Name"


        $RuleName = "Blacklisted IP: - $IP -Inbound"
        $RuleNameOut = "Blacklisted IP: - $IP -Outbound"


        If ($FwRuleNames.Name -NotContains $RuleName)
        {

            Write-Verbose "Creating firewall rule to block inbound connections to $IP"
            New-NetFirewallRule -DisplayName $RuleName -Name $RuleName -Description "Blocks the IP $IP which may be port scanning" -Direction Inbound -RemoteAddress $IP -Action Block -ErrorAction SilentlyContinue | Out-Null

            Write-Verbose "Creating firewall rule to block outbound connections to $IP"
            New-NetFirewallRule -DisplayName $RuleNameOut -Name $RuleNameOut -Description "Blocks the IP $IP which may be port scanning" -Direction Outbound -RemoteAddress $IP -Action Block -ErrorAction SilentlyContinue | Out-Null
            
            Write-Output "[*] Possible Scan Attempt detected from IP Address $IP, please check $PreserveLocation"

        }  # End If
        Else 
        {
                     
            Write-Output "[*] Firewall Rule for $IP already exists: `nRULE NAME: $RuleName"

        }  # End Else

    }  # End ForEach

}  # End Function Block-IPAddress


<#
.SYNOPSIS
Connect to the local firewall and enables logging. It then watches and can alert in the event of a network scan being detected by the script


.PARAMETER OpenPorts
These will be optional ports that the firewall will keep open. If this is not defined this function will automatically discover the listening ports.

.PARAMETER LogFile
Specify the location of firewall log file(s) ending with extension .log. The default value is the NOT CIS Benchmark recommended location which is C:\Windows\System32\logfiles\firewall\pfirewall.log. Separate multiple log files with a comma.

.PARAMETER ExcludeAddresses
This parameter allows you to define allowed port scanners. This value can be set to a single value or an array of IPv4 addresses. Separate values with a comma. This is here for use during penetration testing engagements as well as for vulnerability scanners such as Nessus. If you are excluding the server address of your vulnerability scanner or admin machine I would recommend you have IP Routing Disabled. Check this setting using the command ```ipconfig /all```

.PARAMETER Limit
Defines the number of unsolicited packets that should indicate a port scan is occuring. The default detection value is 5 unsolicited packets.

.PARAMETER ActiveBlockList
Indicates that the Block-IpAddress cmdlet should be used to block any source address that goes over the unsolicited packet limit

.PARAMETER EmailAlert
Indicates that an email should be sent alerting administrators whenever a possible port scan deteciton occurs. Rather than create 50 parameters so you can use the Send-MailMessage cmdlet I am including this as a switch parameter so you can specify this parameter after filling out the required email values yourself or just dont specify


.DESCRIPTION
A tool to provide the user a way to enable local or remote firewalls and then monitor the firewall logs for port scans on the system.


.EXAMPLE
Watch-PortScan -OpenPorts 80,443 -Domain
# This example opens ports 80 and 443 and blocks all other ports. The logs that will be examined are going to be saved to C:\Windows\System32\logfiles\firewall\pfirewall.log. The alert limit is going to be set to 5. Discovered port scanner IP addresses will not be added to the firewall rule block list.

.EXAMPLE
Watch-PortScan -OpenPorts 80,443,445 -LogFile 'C:\Windows\System32\logfiles\firewall\domainfw.log', 'C:\Windows\System32\logfiles\firewall\private.log' -Limit 10 -ActiveBlockList -Domain
# This example opens ports 80, 443, and 445 and blocks all other ports. The domain and private firewall log files will be monitored for port scans. The alert limit is going to be set to 10 and any discovered port scanning IP address will be added to the firewalls blacklist.

.EXAMPLE
@((Get-NetTcpConnection -State Listen).LocalPort | Select-Object -Unique | Sort-Object) | Watch-PortScan -ActiveBlock -Limit 6 -Private -Public
# This example gets a list of currently listening ports on the device and leaves them open while blocking all other ports. The alert limit is set to 6 consecutive unsolicited packets and any discovered port scanning IP addresses are added to the firewalls blocklist..

.EXAMPLE
Watch-PortScan -EmailAlert -ExcludeAddresses '10.10.10.10.', '10.10.10.11' -Domain
# This example gets a list of currently listening ports on the device and leaves them open while blocking all other ports. The alert limit is set to 5 consecutive unsolicited packets and the logs are saved to C:\Windows\System32\logfiles\firewall\pfirewall.log. This will also send an email alert to the email you specify. The file defined in $PreservationLocation will be attached to the email for the admin to review. This also excludes IP addresses 10.10.10.10. and 10.10.10.11 from being detected as port scanners.


.NOTES
Author: Rob Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.Int32, System.Array
A singular port can be specified for -OpenPorts or multiple values can be specified for -OpenPorts


.OUTPUTS
None


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Watch-PortScan {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [String[]]$OpenPorts = ((Get-NetTcpConnection -State Listen,Established,FinWait1,FinWait2,Bound,CloseWait,Closing -ErrorAction SilentlyContinue).LocalPort | Select-Object -Unique | Sort-Object),

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String[]]$LogFile = "C:\Windows\System32\logfiles\firewall\pfirewall.log",

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String[]]$ExcludeAddresses,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Int32]$Limit = 5,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$ActiveBlockList,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$EmailAlert
        )  # End param


    Test-Admin 

    # Log files that are used to keep information for later analysis
    $FileName =  $LogFile.Split('\') | Select-Object -Index (($LogFile.Split('\').Count) - 1)
    $DirectoryName = $LogFile.Replace("\$FileName","")
    $TempLogname = "$DirectoryName\" + ($FileName.TrimEnd('.log')) + "_temp.log"
    $PreserveLocation = "$DirectoryName\Keep_For_Analysis\scan_attempts.log"
    $LogDirectory = "$DirectoryName\Keep_For_Analysis"

    # Variables used for a loop later on
    $ScanCounter = 0
    $ScanFound = $False

    # Defining array variables that will be utilized
    $BlockPortRanges = [System.Collections.ArrayList]::New()
    $BlockIps = [System.Collections.ArrayList]::New()
    $TotalPorts = [uint16]$OpenPorts.Count

    # Defining IP Addresses to filter out normal traffic flows to help prevent false positives
    $IPs = [System.Net.Dns]::GetHostAddresses("$env:COMPUTERNAME").Where({$_.AddressFamily -eq 'InterNetwork'}).IpAddressToString
    $DnsServers = Get-CimInstance -ClassName "Win32_NetworkAdapterConfiguration" | ForEach-Object -MemberName "DNSServerSearchOrder"
    $DnsServers += $ExcludeAddresses

    # Objects that will be used to check for consecutive IP address connections
    $CurrentEntryObject = New-Object -TypeName PSCustomObject -Property @{Date=""; Time=""; Action=""; Protocol=""; SourceIP=""; DestinationIP=""}
    $PreviousEntryObject = New-Object -TypeName PSCustomObject -Property @{Date=""; Time=""; Action=""; Protocol=""; SourceIP=""; DestinationIP=""}


    If ((Test-Path -Path $LogFile) -and ($FileName -like "*.log"))
    {

        Write-Output "[*] Firewall Log file location has been verified."

    }  # End If
    Else
    {
            
        Throw "[!] The path you defined, $LogFile, needs to end in a .log file extension"

    }  # End ELse 


    Write-Verbose "Creating log file and directory location for Log Anaylsis"
    New-Item -Path $LogDirectory -ItemType "Directory" -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -Path $TempLogname,$PreserveLocation -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
 

@"
    Write-Verbose "Getting a list of all the firewall rule names"
    $FirewallRule = New-Object -ComObject HNetCfg.FwPolicy2
    $FwRuleNames = $FirewallRule.Rules | Select-Object -Property "Name"


    Write-Output "[*] Creating Firewall Rules to allow open ports and block all others"

    Write-Verbose "Blocking all uninitated inbound TCP Port Connections"
    For ($n = [uint16]::MinValue; $n -le $OpenPorts.Count ; $n++)
    {

        Switch ([uint16]$n)
        {

            $TotalPorts { 
                [uint16]$Value = (($OpenPorts[($n - 1)]))
                [uint16]$Start = $Value + [uint16]1
                [uint16]$End = 65535
                Write-Debug "$Start to $End"
            } 
            0 {
                [uint16]$Start = $n
                [uint16]$End = ($OpenPorts[$n] - 1)
                Write-Debug "$Start to $End"
            }
            Default { 
                [uint16]$Value = (($OpenPorts[($n - 1)]))
                [uint16]$Start = ($Value + 1)
                [uint16]$End = ($OpenPorts[$n] - 1)
                Write-Debug "$Start to $End" }

        }  # End Switch


        If ($Start -ne $End)
        {

            $BlockPortRanges.Add("$Start-$End") | Out-Null

        }  # End If
        ElseIf ($Start -eq $End)
        {

            $BlockPortRanges.Add("$Start") | Out-Null

        }  # End ElseIf


    }  # End For



    Write-Output "[*] Creating firewall rules"
    ForEach ($BlockPortRange in $BlockPortRanges)
    {

        $StringPortRange = $BlockPortRange.ToString()
        If ($FwRuleNames.Name -NotContains "Block Ports $StringPortRange - Inbound TCP")
        {

            New-NetFirewallRule -DisplayName "Block Ports $BlockPortRange - Inbound TCP" -Description "Blocks inbound ports $BlockPortRange - TCP" -Direction Inbound  -Protocol TCP -LocalPort $BlockPortRange -Action Block -ErrorAction SilentlyContinue | Out-Null

            New-NetFirewallRule -DisplayName "Block Ports $BlockPortRange - Inbound UDP" -Description "Blocks inbound ports $BlockPortRange - UDP" -Direction Inbound  -Protocol UDP -LocalPort $BlockPortRange -Action Block -ErrorAction SilentlyContinue | Out-Null
 
        }  # End If

    }  # End ForEach
    
"@

    $Now = (Get-Date).Ticks
    $LastMinute = ((Get-Date -DisplayHint Time).AddSeconds((-100)).Ticks)

    Write-Verbose "Parsing log file entrys"
    While ($True)
    {
           
        Write-Output "[*] Checking log entries for scanning attempts"
       
        $Logs = Get-Content -Path $LogFile -Tail 5000
   
        ForEach ($Log in $Logs)
        {

            $Entry = $Log.Split()
 
            $PreviousEntryObject = $CurrentEntryObject
            
            $StrDate = $Entry[0]
            $StrTime = $Entry[1] 
            $StrDateTime = "$StrDate $StrTime"

            Try 
            {
                
                $CurrentEntryObjectDate = ([Datetime]::ParseExact($StrDateTime, 'yyyy-MM-dd HH:mm:ss', $Null)).Ticks

            }  # End Try
            Catch 
            {

                Continue

            }  # End Catch
    
            $CurrentEntryObject.Date = $Entry[0]
            $CurrentEntryObject.Time = $Entry[1]
            $CurrentEntryObject.Action = $Entry[2]
            $CurrentEntryObject.Protocol = $Entry[3]
            $CurrentEntryObject.SourceIP = $Entry[4]
            $CurrentEntryObject.DestinationIP = $Entry[5]

                  # Destination IP is this machine                        # The traffic is not from the local machine          # The Source IP is not on allowed list                      # Resutls from the last minute
            If (($IPs -Contains $CurrentEntryObject.DestinationIP) -and ($IPs -NotContains $CurrentEntryObject.SourceIP) -and ($DnsServers -NotContains $CurrentEntryObject.SourceIP) -and (($CurrentEntryObjectDate -le $Now) -and ($CurrentEntryObjectDate -ge $LastMinute)))
            {

                Write-Output "[*] A match has been found, checking to see if the address has been repeated"
                
                If ($CurrentEntryObject.SourceIP -eq $PreviousEntryObject.SourceIP)
                {

                    $ScanCounter++

                    Write-Verbose "Alert limit is set to $Limit consecutive unsolicited packets from the same source IP"
                    If ($ScanCounter -ge $Limit)
                    {
  
                        Write-Output "[!] Alert Limit Has Been Reached"
                        $ScanCounter = 0
                        $ScanFound = $True

                        $IPForEmail = ($CurrentEntryObject.SourceIP).ToString()
                        $DestinationForEmail = ($CurrentEntryObject.DestinationIP).ToString()
                        $ProtocolForEmail = ($CurrentEntryObject.Protocol).ToString()
                        $DateTimeForEmail = ($CurrentEntryObject.Date).ToString() + " " + ($CurrentEntryObject.Time).ToString()

                        If ($EmailAlert.IsPresent)
                        {

                            Write-Output "[*] Alerting admins"

                            $Body = " =======================================================`n PORT SCAN DETECTED: $env:COMPUTERNAME `n=======================================================`n`nSUMMARY: `nA possible port scan was discovered on $env:COMPUTERAME. To examine these results further the firewall logs to review are in C:\Windows\System32\LogFiles\firewall\Keep_For_Analysis. `n`nSCAN INFO: `nSOURCE IP: $IPForEmail `nDESTINATION: $DestinationForEmail `nPROTOCOL: $ProtocolForEmail `nDATE TIME: $DateTimeForEmail`n"
                
                            Send-MailMessage -To $To -From $From -SmtpServer $SmtpServer -Priority High -Subject "ALERT: Attempted Port Scan $env:COMPUTERNAME" -Body $Body

                        }  # End If
                        
                        If ($PSBoundParameters.Key -eq "ActiveBlockList")
                        {

                            If ($BlockIps -NotContains $CurrentEntryObject.SourceIP)
                            {

                                $BadGuyIP = $CurrentEntryObject.SourceIP

                                Write-Output "[*] Scan detected: Adding $BadGuyIP to the block list. If -ActiveBlockList was specified the IP will be blocked shortly"
                                $BlockIps.Add($BadGuyIP)
    
                            }  # End If

                        }  # End If
  
                    }  # End If
  
                }  # End 
  
            }  # End If
            Else
            {
  
                $ScanCounter = 0
            
            }  # End Else
  
        }  # End ForEach
    
        If ($ScanFound -eq $True)
        {

            $ScanDate = Get-Date

            Write-Output "[*] Possible scan attempt Found. Adding log info to $PreservationLocation"
            Add-Content -Path $PreserveLocation -Value "Possible Scan Attempts on $env:COMPUTERNAME at $ScanDate`n`n$Logs`n"


            If ($ActiveBlockList.IsPresent)
            {

                Block-IpAddress -IPAddress $BlockIps

            }  # End If

        }  # End If

        Write-Verbose "Waiting 60 seconds before next check"
        Start-Sleep -Seconds 60

        $Now = (Get-Date).Ticks
        $LastMinute = ((Get-Date -DisplayHint Time).AddSeconds((-100)).Ticks)

    }  # End While Loop

}  # End Function Watch-PortScan

Write-Output "[*] Removing Firewall Rules Created by the last run of this script"
Remove-NetFirewallRule -Description "Blocks inbound ports * - *P" -Direction Inbound

$LogPath = "C:\Windows\System32\LogFiles\Firewall"
$OpenPorts = ((Get-NetTcpConnection -State Listen,Established,FinWait1,FinWait2,Bound,CloseWait,Closing -ErrorAction SilentlyContinue).LocalPort | Select-Object -Unique | Sort-Object) 


Write-Output "[*] Configuring the required Firewall settings"

New-FirewallLogFile -Path $LogPath
Enable-FirewallLogging -Path $LogPath


Write-Output "[*] Monitoring for port scans on localhost"

Watch-PortScan -OpenPorts $OpenPorts -LogFile "$LogPath\domainfw.log" -Limit 5 -EmailAlert
