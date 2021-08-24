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
$Dateregex = "(0[1-9]|1[012])[- /.](0[1-9]|[12][0-9]|3[01])[- /.](19|20)[0-9]{2}"

Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=3; StartTime=(Get-Date).AddHours(-1.2)} | Select-Object -ExpandProperty Message | Out-File -FilePath $TmpEventFile

$IPList = Get-ValidIPAddressFromString -Path $TmpEventFile
ForEach ($IP in $IPList) {

    Write-Verbose "Checking $IP against blacklists"
    Invoke-IPBlacklistCheck -IPAddress $IP -Verbose

    Write-Verbose "Checking $IP domain creation date"
    $Creation = Try { (((Get-WhoIs -Query $IP).Split(' ') | Select-String -Pattern $DateRegex)[0] -Replace 'Comment:','').Trim() } Catch { Clear-Variable -Name Creation -ErrorAction SilentlyContinue }
    $CreationDate = [Datetime]::ParseExact("$Creation", 'yyyy-MM-dd', $Null)

    If (($Creation) -and (($Now.AddYears(-2) -le $CreationDate))) {

        Write-Verbose "Creating an event in MaliciousIPs Event Viewer Tree for a young domain"

        $Message = Write-Output "Domain was found to be less than a year old. WHOIS Information is below: `n" + ($Results  | Out-String -Width 1000)
        Write-EventLog -LogName MaliciousIPs -Source MaliciousIPs -EntryType Information -EventId 2 -Message $Message

    }  # End If

}  # End ForEach

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUm8SueELk1fTHpyElaiadF9P7
# KvCgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FFFV0F/AnuRjhsIKlLxkowR3hOe8MA0GCSqGSIb3DQEBAQUABIIBAB4W6L56xRm4
# 9YejFpHbUy2QSbl4axqDpXNXMpUmQ9W3sZRTrfFQcux1bnfBNEzIlHs0wx187CG0
# iY3UI+eSGe7WAf5O/pM0+chLiyejbvVHPb2Ec3fruE/q5wgWA+ha8yQ+N5S6HOZm
# qUWEKCW/FTZCpmoLNRqYVitvSG/Gy/BEdkurIGIFGHgcKSK4MigMa0vubZfSC7eX
# f0cu19kXVJcavPdNxKkCtzk9DaAY/a/GCoMvqzYAAK53wl/cjvMy4KVlj11EwJ5s
# mDbn2OszjPGxFJ85saSfN4Pjaw+I5ThGOQsIva+G4DudKQXsUyQJabYak+sAVJcJ
# c3ktKmkcCGE=
# SIG # End signature block
