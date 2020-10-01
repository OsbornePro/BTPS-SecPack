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


# REFERNCE: https://www.kittell.net/code/powershell-domain-whois/
    #.Synopsis
    #   Does a raw WHOIS query and returns the results
    #.Example
    #   whois poshcode.org
    #
    #   The simplest whois search
    #.Example
    #   whois poshcode.com
    #
    #   This example is one that forwards to a second whois server ...
    #.Example
    #   whois poshcode.com -NoForward
    #
    #   Returns the partial results you get when you don't follow forwarding to a new whois server
    #.Example
    #   whois domain google.com
    #
    #   Shows an example of sending a command as part of the search.
    #   This example does a search for an exact domain (the "domain" command works on crsnic.net for .com and .net domains)
    #
    #   The google.com domain has a lot of look-alike domains, the least offensive ones are actually Google's domains (like "GOOGLE.COM.BR"), but in general, if you want to look up the actual "google.com" you need to search for the exact domain.
    #.Example
    #   whois n 129.21.1.82 -server whois.arin.net
    # 
    #   Does an ip lookup at arin.net
    #.Notes
    # Future development should look at http://cvs.savannah.gnu.org/viewvc/jwhois/jwhois/example/jwhois.conf?view=markup
    # v0.3 Added documentation, examples, error handling for ip lookups, etc.
    # v0.2 Now strips command prefixes off when forwarding queries (if you want to send the prefix to the forwarded server, specify that server with the original query).
    # v0.1 Now able to re-query the correct whois for .com and .org to get the full information!
 function Get-WhoIs {
    [CmdletBinding()]
    param(
        # The query to send to WHOIS servers
        [Parameter(Position=0, ValueFromRemainingArguments=$true)]
        [string]$query,
 
        # A specific whois server to search
        [string]$server,
 
        # Disable forwarding to new whois servers
        [switch]$NoForward
    )
    end {
        $TLDs = DATA {
          @{
            ".br.com"="whois.centralnic.net"
            ".cn.com"="whois.centralnic.net"
            ".eu.org"="whois.eu.org"
            ".com"="whois.crsnic.net"
            ".net"="whois.crsnic.net"
            ".org"="whois.publicinterestregistry.net"
            ".edu"="whois.educause.net"
            ".gov"="whois.nic.gov"
          }
        }
 
        $EAP, $ErrorActionPreference = $ErrorActionPreference, "Stop"
 
        $query = $query.Trim()
 
        if($query -match "(?:\d{1,3}\.){3}\d{1,3}") {
            Write-Verbose "IP Lookup!"
            if($query -notmatch " ") {
                $query = "n $query"
            }
            if(!$server) { $server = "whois.arin.net" }
        } elseif(!$server) {
            $server = $TLDs.GetEnumerator() |
                Where { $query -like  ("*"+$_.name) } |
                Select -Expand Value -First 1
        }
 
        if(!$server) { $server = "whois.arin.net" }
        $maxRequery = 3
 
        do {
            Write-Verbose "Connecting to $server"
            $client = New-Object System.Net.Sockets.TcpClient $server, 43
 
            try {
                $stream = $client.GetStream()
 
                Write-Verbose "Sending Query: $query"
                $data = [System.Text.Encoding]::Ascii.GetBytes( $query + "`r`n" )
                $stream.Write($data, 0, $data.Length)
 
                Write-Verbose "Reading Response:"
                $reader = New-Object System.IO.StreamReader $stream, [System.Text.Encoding]::ASCII
 
                $result = $reader.ReadToEnd()
 
                if($result -match "(?s)Whois Server:\s*(\S+)\s*") {
                    Write-Warning "Recommended WHOIS server: ${server}"
                    if(!$NoForward) {
                        Write-verbose "Non-Authoritative Results:`n${result}"
                        # cache, in case we can't get an answer at the forwarder
                        if(!$cachedResult) {
                            $cachedResult = $result
                            $cachedServer = $server
                        }
                        $server = $matches[1]
                        $query = ($query -split " ")[-1]
                        $maxRequery--
                    } else { $maxRequery = 0 }
                } else { $maxRequery = 0 }
            } finally {
                if($stream) {
                    $stream.Close()
                    $stream.Dispose()
                }
            }
        } while ($maxRequery -gt 0)
 
        $result
 
        if($cachedResult -and ($result -split "`n").count -lt 5) {
            Write-Warning "Original Result from ${cachedServer}:"
            $cachedResult
        }
 
        $ErrorActionPreference = $EAP
    }
 }  # End Function Get-WhoIs


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


$TmpEventFile = "C:\Windows\Temp\SysmonEvents.txt"

Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=3; StartTime=(Get-Date).AddHours(-1)} | Select-Object -ExpandProperty Message | Out-File -FilePath $TmpEventFile

$IPList = Get-ValidIPAddressFromString -Path $TmpEventFile
ForEach ($IP in $IPList)
{

    $Results = Get-WhoIs -Query $IP -ErrorAction SilentlyContinue
    $ResultsDate = $Results | Select-String -Pattern "Creation Date:"
    $DateLimit = (Get-Date).Year
    
    If (($DateLimit - ($ResultsDate.CreatedDate).Year) -le 2) # This part is NOT working just yet
    {
        
        Write-Verbose "Creating an event in MaliciousIPs Event Viewer Tree for a young domain"

        $Message = Write-Output "Domain was found to be less than a year old. WHOIS Information is below: `n" + ($Results  | Out-String -Width 1000)
        Write-EventLog -LogName MaliciousIPs -Source MaliciousIPs -EntryType Information -EventId 2 -Message $Message
        
    }  # End If

}  # End ForEach  
