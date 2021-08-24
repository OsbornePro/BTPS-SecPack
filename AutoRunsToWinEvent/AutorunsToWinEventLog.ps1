# Authors: Chris Long (@Centurion), Andy Robbins (@_wald0)
# This script executes the Sysinternals Autoruns CLI utility and saves the output to a CSV.
# The resulting CSV entries are written to a Windows Event Log called "Autoruns"

## Code to create the custom Autoruns Windows event log if it doesn't exist
# The following event IDs are in use:
# 1 - Sysinternals Autoruns results
# 2 - Local Group Principals
$LogfileExists = Get-Eventlog -List | Where-Object {$_.logdisplayname -eq "Autoruns"}
If (!($LogfileExists)) {

  New-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog"
  Limit-EventLog -LogName "Autoruns" -OverflowAction OverWriteAsNeeded -MaximumSize 512KB

}  # End If

# Define the path where the Autoruns CSV will be saved
$AutorunsCsv = "c:\Program Files\AutorunsToWinEventLog\AutorunsOutput.csv"

## Autorunsc64.exe flags:
# -nobanner    Don't output the banner (breaks CSV parsing)
# /accepteula  Automatically accept the EULA
# -a *         Record all entries
# -c           Output as CSV
# -h           Show file hashes
# -s           Verify digital signatures
# -v           Query file hashes againt Virustotal (no uploading)
# -vt          Accept Virustotal Terms of Service
#  *           Scan all user profiles

## Normally we'd add a "-Wait" flag to this Start-Process, but it seems to be
## broken when called from RunAs or Scheduled Tasks: https://goo.gl/8NcvcK
$Proc = Start-Process -FilePath "c:\Program Files\AutorunsToWinEventLog\Autorunsc64.exe" -ArgumentList '-nobanner', '/accepteula', '-a *', '-c', '-h', '-s', '-v', '-vt', '*'  -RedirectStandardOut $AutorunsCsv -WindowStyle Hidden -Passthru
$Proc.WaitForExit()
$AutoRunsArray = Import-Csv -Path $AutoRunsCsv

Foreach ($Item in $AutoRunsArray) {

  $Item = Write-Output $Item  | Out-String -Width 1000
  Write-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog" -EntryType Information -EventId 1 -Message $Item

}  # End ForEach

# Collect principals in interesting local groups (Administrators, Remote Desktop Users, and DCOM Users)
# Requires PowerShell 5.1 due to usage of Get-NetLocalGroup and Get-LocalGroupMember

# Get the FQDN of the current computer's domain. Todo: update this method to support foreign security principals in local groups.
$ComputerName = (Get-CimInstance -ClassName Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
$DomainFQDN = $ComputerName.Split(".")[1..($ComputerName.Split(".").length-1)] -Join "."

$LocalGroups = Get-LocalGroup | Where-Object {$_.SID -Match "S-1-5-32-555" -Or $_.SID -Match "S-1-5-32-544" -Or $_.SID -Match "S-1-5-32-562"}

$LocalGroups | ForEach-Object {

    $GroupName = $_
    Get-LocalGroupMember -Name $GroupName | Where-Object { $_.PrincipalSource -Match "ActiveDirectory" } | ForEach-Object {

        $PrincipalName = $_.Name.Split("\")[1] + "@" + $DomainFQDN

        $Member = New-Object -TypeName PSObject
        $Member | Add-Member Noteproperty 'GroupName' $GroupName
        $Member | Add-Member Noteproperty 'PrincipalType' $_.ObjectClass
        $Member | Add-Member Noteproperty 'PrincipalName' $principalname

        $Data = @"
GroupName: $($Member.GroupName)
PrincipalType: $($Member.PrincipalType)
PrincipalName: $($Member.PrincipalName)
"@

        Write-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog" -EntryType Information -EventId 2 -Message $Data

    }  # End ForEach-Object

}  # End ForEach-Object

Write-Verbose "Creating a CSV File containing autoruns information for the day"
$AutoRunsArray | Export-Csv -Path $AutorunsCsv -Delimiter ',' -NoTypeInformation -Force

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUFtJGJ8i8HJHp6N7Wr2FEKvOm
# vVegggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FG73e1AOdUew6tap2zUhuLy7cyBHMA0GCSqGSIb3DQEBAQUABIIBAEnmxDe16CEx
# zW5Iwv0vp7pjgIH9JAs1m5nLiRSbSuMJK8BPQUtBMZnk6SkauRMo4b15H+fOkThD
# MVMBOaqe5Inw0uys6iPZbjXPhp0JCBhyDrxJfHz0q813wBZZMsZUGNP7ZRh0o6r+
# nKTMF1qjNSP4TAj4v6YbNoS1CsNalqJJ/e5xx5/6RnDoxDIVdgFf6gnx26o8Pfqm
# pZ5lWN5pYJfJCGiVu1k4D6oOY/lS+2QHwzvRbpaNAxgisc8v9gTalX1FzIGRpS5A
# a+BWFg5CUig8VMWfu1si4GpqGvKT3g64/uFFA0BuADedQpHCG45qMpVOAxb4X7y0
# oMM/0l2lJ9A=
# SIG # End signature block
