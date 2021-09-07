# This will need to be run as an Administrator

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
https://osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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

    Switch ($PsCmdlet.ParameterSetName) {
        'File' {

            $FileContents = Get-Content -Path $Path -Tail 5000
            ForEach ($Line in $FileContents) {

                If (($Line -Match $Regex) -and ($Obj -notcontains $Matches.Address)) {

                        $Obj += $Matches.Address

                }  # End If

            }  # End ForEach

            Return $Obj

        }  # End File Switch

        'Line' {

            If ($String -Match $Regex) {

                $Obj = $Matches.Address

            }  # End If

            $Obj

        }  # End Default Switch

    }  # End Switch

}  # End Function Get-ValidIPAddressFromString


# REFERNCE: https://www.kittell.net/code/powershell-domain-whois/
<#
.SYNOPSIS
Does a raw WHOIS query and returns the results


.EXAMPLE
Get-WhoIs -Query poshcode.org
# The simplest whois search

.EXAMPLE
Get-Whois poshcode.com
   This example is one that forwards to a second whois server ...

.EXAMPLE
# Get-Whois poshcode.com -NoForward
# Returns the partial results you get when you don't follow forwarding to a new whois server

.EXAMPLE
Get-whois Domain Google.com
# Shows an example of sending a command as part of the search.
# This example does a search for an exact domain (the "domain" command works on crsnic.net for .com and .net domains)
# The google.com domain has a lot of look-alike domains, the least offensive ones are actually Google's domains (like "GOOGLE.COM.BR"), but in general, if you want to look up the actual "google.com" you need to search for the exact domain.

.EXAMPLE
Get-WhoIs n 129.21.1.82 -Server whois.arin.net
# Does an ip lookup at arin.net

.NOTES
Future development should look at http://cvs.savannah.gnu.org/viewvc/jwhois/jwhois/example/jwhois.conf?view=markup
v0.3 Added documentation, examples, error handling for ip lookups, etc.
v0.2 Now strips command prefixes off when forwarding queries (if you want to send the prefix to the forwarded server, specify that server with the original query).
v0.1 Now able to re-query the correct whois for .com and .org to get the full information!
 #>
 Function Get-WhoIs {
    [CmdletBinding()]
        param(
            # The query to send to WHOIS servers
            [Parameter(Position=0, ValueFromRemainingArguments=$True)]
            [String]$Query,

            # A specific whois server to search
            [string]$Server,

            # Disable forwarding to new whois servers
            [Switch]$NoForward)  # End param


    END {

    If (($Query -NotLike "127.0.0.*") -and ($Query -NotLike "192.168.*.*") -and ($Query -NotLike "10.*.*.*") -and ($Query -NotLike "172.16.*.*") -and ($Query -NotLike "169.254.*.*")) {

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
        $Query = $Query.Trim()

        If ($Query -Match "(?:\d{1,3}\.){3}\d{1,3}") {

            Write-Verbose "IP Lookup!"
            If ($Query -NotMatch " ") {

                $Query = "n $Query"

            }  # End If
            If (!$Server) {

                $Server = "whois.arin.net"

            }  # End If
        }  # End If
        ElseIf (!$Server) {

            $Server = $TLDs.GetEnumerator() | Where-Object { $Query -like  ("*"+$_.Name) } | Select-Object -ExpandProperty Value -First 1

        }  # End ElseIf

        If (!$Server) {

            $Server = "whois.arin.net"

        }  # End If

        $MaxRequery = 3

        Do {

            Write-Verbose "Connecting to $Server"
            $Client = New-Object -TypeName System.Net.Sockets.TcpClient $Server, 43

            Try {

                $Stream = $Client.GetStream()

                Write-Verbose "Sending Query: $Query"
                $Data = [System.Text.Encoding]::Ascii.GetBytes( $Query + "`r`n" )
                $Stream.Write($Data, 0, $Data.Length)

                Write-Verbose "Reading Response:"
                $Reader = New-Object -TypeName System.IO.StreamReader $Stream, [System.Text.Encoding]::ASCII

                $Result = $Reader.ReadToEnd()

                If ($Result -Match "(?s)Whois Server:\s*(\S+)\s*") {

                    Write-Warning "Recommended WHOIS server: ${Server}"

                    If (!$NoForward) {

                        Write-verbose "Non-Authoritative Results:`n${Result}"
                        # cache, in case we can't get an answer at the forwarder
                        If (!$CachedResult) {

                            $CachedResult = $Result
                            $CachedServer = $Server

                        }  # End If

                        $Server = $Matches[1]
                        $Query = ($Query -Split " ")[-1]
                        $MaxRequery--

                    }  # End If
                    Else {

                        $MaxRequery = 0

                    }  # End Else
                }   # End If
                Else {

                    $MaxRequery = 0

                }  # End Else

            }  # End Try
            Finally {

                If ($Stream) {

                    $Stream.Close()
                    $Stream.Dispose()

                }  # End If

            }  # End Finally
        } While ($MaxRequery -gt 0)

        $Result
        If ($CachedResult -and ($Result -Split "`n").Count -lt 5) {

            Write-Warning "Original Result from ${CachedServer}:"
            $CachedResult

        }  # End If

        $ErrorActionPreference = $EAP

    }  # End If

  } # End END

}  # End Function Get-WhoIs

# REFERENCE https://community.spiceworks.com/scripts/show/2428-powershell-rbl-blacklist-check-with-email-alerts
Function Invoke-IPBlacklistCheck {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True)]  # End Parameter
            [String[]]$IPAddress)  # End Param


    $LogfileExists = Get-WinEvent -ListLog "MaliciousIPs" -ErrorAction SilentlyContinue
    If (!($LogfileExists)) {

        New-EventLog -LogName MaliciousIPs -Source MaliciousIPs
        Limit-EventLog -LogName "MaliciousIPs" -OverflowAction OverWriteAsNeeded -MaximumSize 64KB

    }  # End If

    ForEach ($IP in $IPAddress) {

        If (($IP -NotLike "127.0.0.*") -and ($IP -NotLike "192.168.*.*") -and ($IP -NotLike "10.*.*.*") -and ($IP -NotLike "172.16.*.*") -and ($IP -NotLike "169.254.*.*")) {

            $BlacklistedOn = @()
            $ReversedIP = ($IP -Split '\.')[3..0] -Join '.'

            # Removed these Blacklist Servers ForOverly Sensitive Results. : 'pbl.spamhaus.org','noptr.spamrats.com','bl.emailbasura.org','tor.ahbl.org','dynip.rothen.com','bl.spamcannibal.org','dnsbl.ahbl.org','spam.spamrats.com','sbl.spamhaus.org','zen.spamhaus.org'
            $BlacklistServers = @(
                'b.barracudacentral.org'
                'spam.rbl.msrbl.net'
                'bl.deadbeef.com'
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
                'http.dnsbl.sorbs.net'
                'images.rbl.msrbl.net'
                'ips.backscatterer.org'
                'ix.dnsbl.manitu.net'
                'korea.services.net'
                'misc.dnsbl.sorbs.net'
                'ohps.dnsbl.net.au'
                'omrs.dnsbl.net.au'
                'orvedb.aupads.org'
                'osps.dnsbl.net.au'
                'osrs.dnsbl.net.au'
                'owfs.dnsbl.net.au'
                'owps.dnsbl.net.au'
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
                'short.rbl.jp'
                'smtp.dnsbl.sorbs.net'
                'socks.dnsbl.sorbs.net'
                'spam.abuse.ch'
                'spam.dnsbl.sorbs.net'
                'spamlist.or.kr'
                'spamrbl.imp.ch'
                't3direct.dnsbl.net.au'
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

            ForEach ($Server in $BlacklistServers) {

                $FQDN = "$ReversedIP.$Server"
                Try {

                    $Null = [System.Net.Dns]::GetHostEntry($FQDN)
                    $BlacklistedOn += $Server

                }  # End Try
                Catch {

                    Continue

                }  # End Catch

            }  # End ForEach

            If ($BlacklistedOn.Count -gt 3) {

                Write-Verbose "Create an event in MaliciousIPs in Event Viewer Tree"
                Foreach ($Item in $BlacklistedOn) {

                    $EventMessage = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=3} | Where-Object -Property Message -like "*$IP*" | Select-Object -First 1 -ExpandProperty Message | Out-String
                    $Message = "IP Address was found to be on the following Blacklists: `n`nIP Address: $IP`nBlacklist: " + (Write-Output $Item  | Out-String -Width 1000) + "`n`n" + (Write-Output $EventMessage | Out-String -Width 1000)

                    Write-EventLog -LogName MaliciousIPs -Source MaliciousIPs -EntryType Information -EventId 1 -Message $Message

                }  # End ForEach

            }  # End If

        }  # End If

    }  # End ForEach

}  # End Function Invoke-IPBlacklistCheck

$Results = @()
$Now = Get-Date
$TmpEventFile = "C:\Windows\Temp\SysmonEvents.txt"
$Dateregex = "(\d{4})-(\d{1,2})-(\d{1,2})"

Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=3; StartTime=(Get-Date).AddHours(-1.2)} | Select-Object -ExpandProperty Message | Out-File -FilePath $TmpEventFile

$IPList = Get-ValidIPAddressFromString -Path $TmpEventFile
ForEach ($IP in $IPList) {

    Write-Verbose "Checking $IP against blacklists"
    Invoke-IPBlacklistCheck -IPAddress $IP -Verbose

    Write-Verbose "Checking $IP domain creation date"
    $Creation = Try { (((Get-WhoIs -Query $IP).Split(' ') | Select-String -Pattern $DateRegex)[0] -Replace 'Updated:','').Replace("Updated:","").Trim() } Catch { Clear-Variable -Name Creation -ErrorAction SilentlyContinue }
    $CreationDate = [Datetime]::ParseExact("$Creation", 'yyyy-MM-dd', $Null)

    If (($Creation) -and (($Now.AddYears(-2) -le $CreationDate))) {

        Write-Verbose "Creating an event in MaliciousIPs Event Viewer Tree for a young domain"

        $Message = Write-Output "Domain was found to be less than a year old. WHOIS Information is below: `n" + ($Results  | Out-String -Width 1000)
        Write-EventLog -LogName MaliciousIPs -Source MaliciousIPs -EntryType Information -EventId 2 -Message $Message

    }  # End If

}  # End ForEach
