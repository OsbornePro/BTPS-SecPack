# This script is used to check for users who have signed into devices that are outside their normally assigend devices
#===========================================================================
# REQUIREMENTS
#===========================================================================
# - This will require a CSV file containing a ComputerName header and Name header and SamAccountName header
# - The script needs to be run on a domain controller logging Event ID 4624
# - This script requires a SamAccountName and a Name for parsing the event logs. I have this set on lines 91-94 using the imported Name value from UserComputerList.csv
# --------------------------------------------------------------------------

# Csv file containing the headers ComputerName and Name
$CsvInformation = Import-Csv -Path "C:\Users\Public\Documents\UserComputerList.csv" -Delimiter ','
$UserList = $CsvInformation | Select-Object -Property Name,SamAccountName -Unique

# Array of Shared Computer Names is for excluding computers that may be shared such as conference room computers that may be signed into
$SharedComputerIPs = @('10.0.1.1','10.0.2.2','10.0.3.3')

# Regex used for filtering event log
[regex]$Ipv4Regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’

# Primary Domain Controller and DNS Server
$PDC = ([ADSI]”LDAP://RootDSE”).dnshostname
$FinalResult = @()

$DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$Domain = $DomainObj.Forest.Name
$DHCPServer = Get-ADObject -SearchBase "cn=configuration,$DistinguishedName" -Filter "objectclass -eq 'dhcpclass' -AND Name -ne 'dhcproot'" | Select-Object -ExpandProperty "Name"

<#
.SYNOPSIS
This PowerShell script is useful in an environment where users can log into any computer but are assigned maybe 1, 2, or 3+ computers.

.DESCRIPTION
What this script does is query the event log for the last 24 hours. Anywhere a successful logon happens (Event ID 4624) the IP Address is noted and compared to the assigned IP Address list located in a CSV File you create. You can then have it notify you of the sign in by email. This is a little niche to a smaller environment. I learned a lot writing this one and will do a blog on it at https://powershell.org

IMPORTANT: For this to work you will need a CSV file containing the user and their assigned devices.

  That info is imported from the CSV before it can be worked with.

.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Get-UserSid {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory = $True,
                    Position = 0,
                    ValueFromPipeline=$True,
                    ValueFromPipelineByPropertyName=$True,
                    HelpMessage = "Enter a SamAccountName for the user profile. Example: OsbornePro\rob.osborne")] # End Parameter
            [String[]]$SamAccountName) # End param

    $ObjUser = New-Object -TypeName System.Security.Principal.NTAccount($SamAccountName)

    $ObjSID = $ObjUser.Translate([System.Security.Principal.SecurityIdentifier])

    If (!($Null -eq $ObjSID))
    {

        $ObjSID.Value

    } # End If
    Else
    {

        Write-Output "[X] SID Lookup failed."

    } # End Else

} # End Function Get-UserSid


ForEach ($Assignment in $UserList)
{

    Write-Host "[*] Getting SamAccountName and SID values..." -ForegroundColor 'Cyan'

    $SamAccountName = $Assignment.SamAccountName
    $SID = Get-UserSid -SamAccountName $SamAccountName
    $Name = $Assignment.Name

    Write-Host "[*] Getting computers assigned to $SamAccountName" -ForegroundColor 'Cyan'
    $ResolveTheseComputerNames = $CsvInformation | Where-Object -Property 'Name' -like $Name | Select-Object -ExpandProperty 'ComputerName'


    Write-Host "[*]Translating computernames to Ip Addresses for searching the event logs." -ForegroundColor 'Cyan'
    $SearchIP = @()
    ForEach ($Device in $ResolveTheseCOmputerNames)
    {

        $Ipv4Address = (Resolve-DnsName -Name $Device -Server $PDC -Type A -ErrorAction SilentlyContinue).IPAddress

        If ($Ipv4Address)
        {

            $SearchIP += $Ipv4Address

        } # End If

    } # End ForEach

    $ComputerAssignments = @()
    $ComputerAssignments = $SharedComputerIPs + $SearchIP

    Write-Host "[*] Getting log on events for $SamAccountName. Please wait..." -ForegroundColor 'Cyan'

    [array]$UserLogonEvents = @()
    # This event checks the last 24 hours (86400000)
    [array]$UserLogonEvents = Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='TargetUserName']=`'$SamAccountName`']]" -ErrorAction SilentlyContinue

    [array]$EventLoggedInIps = @()
    # Selects one of each IP address found that was accessed
    [array]$EventLoggedInIps = $UserLogonEvents.Message -Split "`n" | Select-String -Pattern $Ipv4Regex | Select-Object -Unique

    [System.Collections.ArrayList]$UnusualSignInIps = @()
    [System.Collections.ArrayList]$UnusualSignInHostname = @()

    # Compares the assigned computers to signed in devices
     ForEach ($EventIp in $EventLoggedInIps)
    {

        $CompareValue = ($EventIp | Out-String).Replace('Source Network Address:	','').Trim()

        # BELOW SWITCH OPTIONS SHOULD BE SET TO MATCH SUBNETS IN YOUR ENVIRONMENT THAT ARE ON WIFI OR VPN THAT CHANGE ##############################################################
        Switch -Wildcard ($CompareValue)
        {
            "10.0.0.*" {
                    $DhcpResolvedHost = Invoke-Command -HideComputerName $DHCPServer -ScriptBlock {Get-DhcpServerv4Lease -ComputerName localhost -ScopeID '10.0.0.0'}; $SingleHost = $DhcpResolvedHost.Where({[IPAddress]$_.Ipaddress -like $CompareValue})
                }
            "10.1.0.*" {
                    $DhcpResolvedHost = Invoke-Command -HideComputerName $DHCPServer -ScriptBlock {Get-DhcpServerv4Lease -ComputerName localhost -ScopeID '10.1.0.0'};; $SingleHost = $DhcpResolvedHost.Where({[IPAddress]$_.Ipaddress -like $CompareValue})
                }
            "10.2.0.*" {
                    $DhcpResolvedHost = Invoke-Command -HideComputerName $DHCPServer -ScriptBlock {Get-DhcpServerv4Lease -ComputerName localhost -IPAddress -ScopeID '10.2.0.0'}; $SingleHost = $DhcpResolvedHost.Where({[IPAddress]$_.Ipaddress -like $CompareValue})
                }
            "10.3.0.*"  {
                    $DhcpResolvedHost = Invoke-Command -HideComputerName $DHCPServer -ScriptBlock {Get-DhcpServerv4Lease -ComputerName localhost -ScopeID '10.3.0.0'}; $SingleHost = $DhcpResolvedHost.Where({[IPAddress]$_.Ipaddress -like $CompareValue})
                }
            Default {
                    Remove-Variable -Name DhcpResolvedHost -ErrorAction SilentlyContinue
                }
        }  # End Switch

        If ($Null -eq $SingleHost)
        {
            Try
            {

                $DnsCheck = ((Resolve-DnsName -Name $CompareValue -Server "$env:COMPUTERNAME.$Domain" -DnssecOk -ErrorAction SilentlyContinue).NameHost).Replace(".$Domain","")

                If ($ResolveTheseComputerNames -contains $DnsCheck)
                {

                    $ComputerAssignments += ($CompareValue)

                }  # End If

            }  # End Try
            Catch
            {

                Write-Host "[*] Could not resolve $CompareValue to an hostname" -ForegroundColor Cyan

            }  # End Catch

            If (($ComputerAssignments -notcontains $CompareValue) )# -and ($CompareValue -notlike "10.10.10.*")) # 10.10.10.* can be used to exclude VPN subnets or whatever
            {

                $UnusualSignInIps += ($CompareValue)
                $UnusualSignInHostname += ((Resolve-DnsName -Name $CompareValue -Server "$env:COMPUTERNAME.$Domain" -DnssecOk -ErrorAction SilentlyContinue).NameHost).Replace(".$Domain","")

            } # End If

        }  # End If
        Else
        {

            If ($ResolveTheseComputerNames -notcontains $SingleHost.Hostname.Replace("$env:USERDNSDOMAIN",""))
            {

                $UnusualSignInIps += $SingleHost.IPAddress
                $UnusualSignInHostname += $SingleHost.Hostname.Replace("$env:USERDNSDOMAIN","")

            }  # End If

        }  # End Else

        Remove-Variable -Name SingleHost,DhcpResolvedHost -ErrorAction SilentlyContinue

    } # End ForEach

    If ($UnusualSignInIps)
    {

        $Obj = New-Object -TypeName PSObject -Property @{User=$SamAccountName; SID=$SID; IPv4Location="$UnusualSignInIps";Hostnames="$UnusualSignInHostname"}
        $FinalResult += $Obj

    } # End If
    Else
    {

        Write-Host "[*] No unexpected logon events found for $SamAccountName" -ForegroundColor 'Green'

    } # End Else

} # End ForEach

# Build Email to send final results to inform admins
$Css = @"
<style>
table {
    font-family: verdana,arial,sans-serif;
        font-size:11px;
        color:#333333;
        border-width: 1px;
        border-color: #666666;
        border-collapse: collapse;
}
th {
        border-width: 1px;
        padding: 8px;
        border-style: solid;
        border-color: #666666;
        background-color: #dedede;
}
td {
        border-width: 1px;
        padding: 8px;
        border-style: solid;
        border-color: #666666;
        background-color: #ffffff;
}
</style>
"@ # End CSS

$PreContent = "<Title>NOTIFICATION: Unusual Sign In: $env:COMPUTERNAME</Title>"
$NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
$PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
$MailBody = $FinalResult | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on users who have signed into devices they are not assigned in the last 24 hours<br><br><hr><br><br>" | Out-String

Send-MailMessage -From FromEmail -To ToEmail -Subject "Unusual Login Occurred" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -Credential $Credential -UseSsl -Port 587

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbL7yYipCtbieH2Qj5+HCtsV1
# Ubqgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FAJYuWzlKaDwb3+bKwjP30hyu5m6MA0GCSqGSIb3DQEBAQUABIIBAINb814LKe8r
# xJfWmn2/dHvkgQE+2OTtprVK3MjW/7OX+hL5IwI3DnXXuBBByjFyYoLADxXGVGWg
# Qdr/8883+BBNLzxIUYfv213snLexylbr3C3jcvhkUIHyPIl6Xdys3vBOYcwks9aC
# lIaYVWWPN9qOVS0vHn77BPYlYeJ0/3W6DC6Z5Zbjze09yTHfc0pArDosgu+wN2Mw
# l2DDHfQM6ez+T+7UOYkJrMqAVf8f9afy14HpSBGhV+KAfv72nH5ZAVwEM3lUwLB0
# PbYud2PU1cPZ3sW/ZPccdvmjS9YQtnD51oG20HwGKs2/KQIUbRPNG6jafog0N4kS
# GlSbR4rVozw=
# SIG # End signature block
