<#
.SYNOPSIS
This cmdlet is used to discover new devices that have joined the network based on Client ID History of the DHCP Servers.


.PARAMETER DhcpServers
This parameter defines an array of DHCP servers in the environment

.PARAMETER ComparePath
This parameter defines the location of the csv file containing MAC history information. If the file does not exist it will be created.

.PARAMETER MacVendorps1
This parameter defines where the locations of the Get-MacVendor.ps1 file is


.DESCRIPTION
Find-NewDevices was made to discover new devices to have joined the network based on Client ID histroy of the DHCP Servers. This was made for System Administrators and does not take any input


.NOTES
Author: Robert H. Osborne
Contact: rosborne@osbornepro.com
Alias: tobor


.EXAMPLE
Find-NewDevices -DhcpServers 'DHCP1','10.10.10.10','DHCP3.domain.com' -ComparePath 'C:\DhcpHistory.csv' -MacVendorps1 .\Get-MacVendor.ps1
# This example discvoers never before seen devies on the 3 different DHCP servers and sends an email if any are discovered.


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
None


.OUTPUTS
None

#>
Function Find-NewDevices {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="Define the DHCP server or servers for the environment.")]  # End Parameter
            [String[]]$DhcpServers,

            [Parameter(
                Mandatory=$True,
                Position=1,
                HelpMessage="Define the full path and file name to the csv file that will contain the MAC address history records.")]  # End Parameter
            [String]$ComparePath,

            [Parameter(
                Mandatory=$True,
                Position=2,
                HelpMessage="Define the full path and file name of the file containing the Get-MacVendor.ps1 file and cmdlet")]  # End Parameter
            [String]$MacVendorps1

        )  # End param

    Import-Module -Name DhcpServer

    ForEach ($DhcpServer in $DhcpServers) {

        Clear-Variable TableInfo,MailBody,PreContent,PostContent,NoteLine -ErrorAction SilentlyContinue

        Write-Verbose "[*] Obtaining Scope Values"
        $Scopes = @()
        $Scopes = (Get-DhcpServerv4Scope -ComputerName $DhcpServer | Select-Object -ExpandProperty "ScopeID").IPAddressToString

        Write-Verbose '[*] Finding Active Address Leases'
        Try {

            Write-Verbose "[*] Building list of all clients in all DHCP scopes on $DhcpServer"

            $CurrentDhcpList = @()
            $CurrentDhcpList = ForEach ($Scope in $Scopes) {

                Get-DHCPServerv4Lease -ComputerName $DhcpServer -ScopeID $Scope -AllLeases -ErrorAction SilentlyContinue | Where-Object { $_.AddressState -like '*Active' }

            } # End Foreach

            If (Test-Path -Path "$ComparePath") {

                Write-Verbose "[*] List of known MAC Addresses has been found."

            } # End If
            Else {

                Write-Verbose "[*] Initial Build of file containing MAC Address history is being created at $ComparePath"
                $CurrentDhcpList | Select-Object -Property ClientID,IPAddress,ScopeID,Hostname,AddressState,LeaseExpiryTime | Export-Csv -Path "$ComparePath" -NoTypeInformation

            } # End Else

            $HistoryDhcpList = Import-Csv -Path "$ComparePath" -Header ClientID

            If ($CurrentDhcpList) {

                Write-Verbose "[*] Comparing Client ID History with Current Leases"

                $NewMacAddresses = @()
                $NewMacAddresses = (Compare-Object -ReferenceObject $HistoryDhcpList -DifferenceObject $CurrentDhcpList -Property ClientId | Where-Object {$_.SideIndicator -like "=>"}) | Select-Object -Property ClientId -ExcludeProperty SideIndicator -ExpandProperty ClientId -Unique

            } # End If
            Else {

                Write-Output "[!] There were not any DHCP clients retrieved from $DhcpServer"
                Break

            } # End Else

            If ($NewMacAddresses) {

                Write-Verbose "[*] Obtaining client lease information for newly found devices. "

                $AllInfo = @()
                $AllInfo = ForEach ($Scope in $Scopes) {
                    # Uncomment and modify the where-object part of this pipe if you wish to exclude certain hostnames for whatever reason
                    (Get-DhcpServerv4Lease -ComputerName $DhcpServer -ClientId $NewMacAddresses -ScopeId $Scope -ErrorAction SilentlyContinue) # | Where-Object -Property HostName -NotLike "DESKTOP*"

                } # End Foreach


                Write-Verbose "[*] Updating Client ID History"
                If ($AllInfo) {

                    Write-Verbose "[*] Appending list of known MAC Addresses"
                    $AllInfo | Select-Object -Property IPAddress,ScopeID,ClientID,Hostname,AddressState,LeaseExpiryTime | Export-Csv -Path $ComparePath -Append # Updates the HistoryDhcpList File

                }  # End If
                Else {

                    Write-Verbose "[*] No accompanying information obtained for that MAC Address"

                }  # End Else

                Write-Verbose "[*] Getting Vendor Information from MAC Addresses of newly discovered devies"
                Import-module -Function ."$MacVendorps1" -Force

                $VendorList = @()
                $VendorList = Get-MACVendor -MacAddress $NewMacAddresses

                If (!($VendorList)) {

                    Write-Output "[*] No matching vendor could be determined from the current MAC vendor list. If you believe this to be an error check the Get-MacVendor.ps1 file at $MacVendorps1"

                } # End If

            }  # End If
            Else {

                Write-Output "[*] No new devices were discovered on $DhcpServer."

            }  # End Else

        }  # End Try
        Catch {

            Write-Output "[x] Error encountered with $DhcpServer"
            $Error[0]

        }  # End Catch
        Finally {

            Import-Module -Function ."$MacVendorps1" -Force

            $Table = @()
            $Table = ForEach ($Vendor in $AllInfo) {

                $VendorAssignment = Get-MacVendor -MACAddress $Vendor.ClientId

                New-Object -TypeName PSObject -Property @{DhcpServer = $DhcpServer
                                                          HostName = $Vendor.HostName
                                                          Scope = $Vendor.ScopeId
                                                          IPAddress = $Vendor.IPAddress
                                                          ClientId = $Vendor.ClientId
                                                          Vendor = $VendorAssignment.Vendor

                 } # End Property

             } # End ForEach

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
"@

        Write-Verbose 'Generating Information for email...'

        $TableInfo = $Table | Select-Object -Property Vendor,HostName,IPAddress,ClientId
        $PreContent = "<Title>Newest Devices to have joined the Netowrk</Title>"
        $NoteLine = "$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"

        $MailBody = $TableInfo | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "This is a list of the newest devices to have joined the Network." | Out-String

            If ($Table) {

                Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: New Device Check $DhcpServer" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -UseSSL -Port 587  -Credential $Credential

                Write-Verbose 'Email sent.'

            } # End if
           Else {

                Write-Verbose "No new devices found."

           } # End Else

        } # End Finally

    } # End Foreach DHCP Server

} # End Function

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0A9mVW/dshQtLe0eTp5zb2Vo
# JfWgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FKMNM2zJRN+gY09i5qwFx8oxRoO+MA0GCSqGSIb3DQEBAQUABIIBACF9JDO0BiYs
# tPP8TvLO8cOCpeELd56zyAoxW7eJWtZDln/AR6+varc1j8zo4S2YELffifPPQeMh
# VdffbAQxDqNb4BKEtyO0Wbwz13AwEAa6q8JrQwU8Egdgg9xdGLMQnZia9ec3VOsh
# BYMaER7Z32lkA1BXQ2R3JDzlZAoCZkgBOCbLG/rV4k4WYAivlxWJMjxdzy0ZSivT
# Bc102eeRsPd0EuXb5IWg9pumMEGYtSPoiiNZDR4IeziccyOd0xetLRpWUA5W3Uwi
# dOR08rXNy0lJ8TOB2hfRZb+hk40fgmZtktlj6bshqOq4KyZf1vZ8Ss3gQfBgg/q1
# W6ObeHFFFqU=
# SIG # End signature block
