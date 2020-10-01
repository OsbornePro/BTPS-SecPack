# GET YOUR API KEY FROM https://user.whoisxmlapi.com/
$APIKey = "<Your API Key Here>"
$Server = 1.1.1.1


<#
.SYNOPSIS
This cmdlet is used to extract all of the unique IPv4 addresses out from each line of a log file


.DESCRIPTION
Use a ForEach type statement to extract unique IPv4 address out from each line of a log file


.PARAMETER String
Defines the string of text that the regular expression of an IPv4 address should be tested for

.PARAMETER Path
Defines the path to a file you want to grab unique IP addresses out out


.EXAMPLE
ForEach ($Line in (Get-Content -Path C:\Temp\firewall.log)) { Get-ValidIPAddressFromString -String $Line }
# This example parses the text file firewall.log and lists any IPv4 Addresses found on each line

.EXAMPLE
Get-ValidIpAddressFromString -Path C:\Windows\System32\LogFiles\Firewall\domainfw.log


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
System.String


.OUTPUTS
System.String

#>
Function Get-ValidIPAddressFromString {
    [CmdletBinding(DefaultParameterSetName="Line")]
        param(
            [Parameter(
                ParameterSetName="Line",
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="`n[H] Enter a string to extract the IPv4 address out of `n[E] EXAMPLE: Log File 8/6/2020 10.10.10.10. DENY TCP")]  # End Parameter
            [String]$String,
        
            [Parameter(
                ParameterSetName="File",
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$Path)  # End param
       

    $Obj = @()
    $Regex=‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’

    Switch ($PsCmdlet.ParameterSetName)
    {
        'File' {

            $FileContents = Get-Content -Path $Path -Tail 5000
            ForEach ($Line in $FileContents)
            {

                If (($Line -Match $Regex) -and ($Obj -notcontains $Matches.Address))
                {
    
                        $Obj += $Matches.Address
        
                }  # End If



            }  # End ForEach
            
            Return $Obj
        
        }  # End File Switch

        'Line' {
        
            If ($String -Match $Regex)
            {
                
                $Obj = $Matches.Address

            }  # End If

            $Obj

        }  # End Default Switch

    }  # End Switch 

}  # End Function Get-ValidIPAddressFromString

# Reference https://itsallinthecode.com/powershell-get-whois-information/
Function Get-ValidDate ($Value, $Date) {
    $DefaultDate = $Value."$($Date)Date"
    $NormalizedDate = $Value.RegistryData."$($Date)DateNormalized"
             
    $DefaultDate = $Value."$($Date)Date"
    $NormalizedDate = $Value.RegistryData."$($Date)DateNormalized"

    If (![String]::IsNullOrEmpty($DefaultDate)) 
    {

        Get-Date -Date $DefaultDate

    }  # End If
    
    Return [DateTime]::ParseExact($NormalizedDate, "yyyy-MM-dd HH:mm:ss UTC", $Null)
     
}  # End Function Get-ValidDate


Function Get-WhoIsLookupInfo {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$True)]  # End Parameter
            [String]$APIKey,
    
            [Parameter(
                Mandatory=$True)]  # End Parameter
            [String[]]$DomainName)  # End param


    $Responses = @()

    $DomainName | ForEach-Object {

        $RequestUri = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=$APIKey&domainName=$_&outputFormat=JSON"

        $Responses += Invoke-RestMethod -Method GET -Uri $RequestUri

    }  # End ForEach-Object

    $Properties = "DomainName", "DomainNameExt",
        @{N = "CreatedDate"; E = { Get-ValidDate -Value $_ "Created" } },
        @{N = "UpdatedDate"; E = { Get-ValidDate -Value $_ "Updated" } },
        @{N = "ExpiresDate"; E = { Get-ValidDate -Value $_ "Expires" } },
        "RegistrarName",
        "ContactEmail",
        "EstimatedDomainAge",
        @{N = "Contact"; E = { ($_.Registrant | Select-Object -Property * -ExcludeProperty RawText ).PSObject.Properties.Value -Join ", " } }

    $WhoIsInfo = $Responses.WhoisRecord | Select-Object -Property $Properties
    
    Return $WhoIsInfo

}  # End Function Get-WhoIsLookupInfo


# REFERENCE https://community.spiceworks.com/scripts/show/2428-powershell-rbl-blacklist-check-with-email-alerts
Function Invoke-IPBlacklistCheck {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True)]  # End Parameter
            [String[]]$IPAddress)  # End Param


    $LogfileExists = Get-Eventlog -List | Where-Object {$_.logdisplayname -eq "BlacklistedIPs"}
    If (!($LogfileExists))
    {

        Write-Verbose "Creating MaliciousIPs event log tree"
        New-EventLog -LogName MaliciousIPs -Source MaliciousIPs
        Limit-EventLog -LogName "MaliciousIPs" -OverflowAction OverWriteAsNeeded -MaximumSize 64KB
        
        Write-Verbose "Creating directory to save log info"
        New-Item -Path "C:\Program Files\BlacklistedIPs" -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

    }  # End If

    ForEach ($IP in $IPAddress)
    {

        $BlacklistedOn = @()
        $ReversedIP = ($IP -Split '\.')[3..0] -Join '.'
        $BlacklistServers = @(
            'b.barracudacentral.org'
            'spam.rbl.msrbl.net'
            'zen.spamhaus.org'
            'bl.deadbeef.com'
            'bl.emailbasura.org'
            'bl.spamcannibal.org'
            'bl.spamcop.net'
            'blackholes.five-ten-sg.com'
            'blacklist.woody.ch'
            'bogons.cymru.com'
            'cbl.abuseat.org'
            'cdl.anti-spam.org.cn'
            'combined.abuse.ch'
            'combined.rbl.msrbl.net'
            'db.wpbl.info'
            'dnsbl-1.uceprotect.net'
            'dnsbl-2.uceprotect.net'
            'dnsbl-3.uceprotect.net'
            'dnsbl.ahbl.org'
            'dnsbl.cyberlogic.net'
            'dnsbl.inps.de'
            'dnsbl.njabl.org'
            'dnsbl.sorbs.net'
            'drone.abuse.ch'
            'drone.abuse.ch'
            'duinv.aupads.org'
            'dul.dnsbl.sorbs.net'
            'dul.ru'
            'dyna.spamrats.com'
            'dynip.rothen.com'
            'http.dnsbl.sorbs.net'
            'images.rbl.msrbl.net'
            'ips.backscatterer.org'
            'ix.dnsbl.manitu.net'
            'korea.services.net'
            'misc.dnsbl.sorbs.net'
            'noptr.spamrats.com'
            'ohps.dnsbl.net.au'
            'omrs.dnsbl.net.au'
            'orvedb.aupads.org'
            'osps.dnsbl.net.au'
            'osrs.dnsbl.net.au'
            'owfs.dnsbl.net.au'
            'owps.dnsbl.net.au'
            'pbl.spamhaus.org'
            'phishing.rbl.msrbl.net'
            'probes.dnsbl.net.au'
            'proxy.bl.gweep.ca'
            'proxy.block.transip.nl'
            'psbl.surriel.com'
            'rbl.interserver.net'
            'rdts.dnsbl.net.au'
            'relays.bl.gweep.ca'
            'relays.bl.kundenserver.de'
            'relays.nether.net'
            'residential.block.transip.nl'
            'ricn.dnsbl.net.au'
            'rmst.dnsbl.net.au'
            'sbl.spamhaus.org'
            'short.rbl.jp'
            'smtp.dnsbl.sorbs.net'
            'socks.dnsbl.sorbs.net'
            'spam.abuse.ch'
            'spam.dnsbl.sorbs.net'
            'spam.spamrats.com'
            'spamlist.or.kr'
            'spamrbl.imp.ch'
            't3direct.dnsbl.net.au'
            'tor.ahbl.org'
            'tor.dnsbl.sectoor.de'
            'torserver.tor.dnsbl.sectoor.de'
            'ubl.lashback.com'
            'ubl.unsubscore.com'
            'virbl.bit.nl'
            'virus.rbl.jp'
            'virus.rbl.msrbl.net'
            'web.dnsbl.sorbs.net'
            'wormrbl.imp.ch'
            'xbl.spamhaus.org'
            'zombie.dnsbl.sorbs.net')

        ForEach ($Server in $BlacklistServers)
        {

            $FQDN = "$ReversedIP.$Server"
            Try
            {

                $Null = [System.Net.Dns]::GetHostEntry($FQDN)
                $BlacklistedOn += $Server

            }  # End Try
            Catch 
            { 

                Continue

            }  # End Catch

        }  # End ForEach

        If ($BlacklistedOn.Count -gt 0)
        {

            Write-Verbose "Create an event in BlacklistIPs Event Viewer Tree"
            Foreach ($Item in $BlacklistedOn) 
            {

                $Message = Write-Output "IP Address was found to be on the following Blacklists: `n" + ($Item  | Out-String -Width 1000)
                Write-EventLog -LogName MaliciousIPs -Source MaliciousIPs -EntryType Information -EventId 1 -Message $Message

            }  # End ForEach

        }  # End If

    }  # End ForEach

}  # End Function Invoke-IPBlacklistCheck


$Results = @()
$TmpEventFile = "C:\Windows\Temp\SysmonEvents.txt"

Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=3; StartTime=(Get-Date).AddHours(-1)} | Select-Object -ExpandProperty Message | Out-File -FilePath $TmpEventFile

$IPList = Get-ValidIPAddressFromString -Path $TmpEventFile
ForEach ($IP in $IPList)
{

    $DomainName = Resolve-DnsName -Name $IP -Server $Server -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue
    If ($DomainName)
    {
        
        $Results += Get-WhoIsLookupInfo -APIKey $APIKey -DomainName $DomainName -ErrorAction SilentlyContinue

    }  # End If

    ForEach ($Result in $Results)
    {
    
        $DateLimit = (Get-Date).Year
        If (($DateLimit - ($Result.CreatedDate).Year) -le 2)
        {
        
            Write-Verbose "Creating an event in MaliciousIPs Event Viewer Tree for a young domain"

            $Message = Write-Output "Domain was found to be less than a year old: `n" + ($Result  | Out-String -Width 1000)
            Write-EventLog -LogName MaliciousIPs -Source MaliciousIPs -EntryType Information -EventId 2 -Message $Message
        
        }  # End If
    
    }  # End ForEach

}  # End ForEach  
