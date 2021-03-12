# This script is for extracting the IMPHASH and MD5 Hash from Sysmon logs in order to compare the hash to a whitelist of known Windows Processes. This will then log any processes that do not appear on the whitelist
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# IMPORTANT : GET A VIRUS TOTAL API KEY FROM https://www.virustotal.com/gui/join-us and place it in the value below
$VirusTotalApiKey = ''

$WhitelistPath = "$env:USERPROFILE\Downloads\BTPS-SecPack-Master\Sysmon\Whitelist.csv"
# To help you add more to your whitelist I have included the commands I used to build this one below
# Create a collection of files to get hashes of and move the results into a text file in case you have large amounts of files to add
# Get-ChildItem -Path 'C:\Program Files\','C:\Program Files (x86)','C:\Windows','C:\Sysinternals\' -Exclude "PsExec.exe","PsExec64.exe","*.log","*.conf","*.config","*.txt" -Recurse -ErrorAction SilentlyContinue -File -Force | Select-Object -ExpandProperty "FullName" | Out-File -FilePath .\Whitelist.txt -Append
#
# This command grabs the file name and MD5 hash and places the values into a CSV file
# Get-Content .\Whitelist.txt | ForEach-Object { $Md5Hash = Get-FileHash -Path $_ -Algorithm MD5 | Select-Object -ExpandProperty Hash; $FileName = $_.Split('\')[-1]; $Object = New-Object -TypeName PSObject -Property @{FileName=$FileName; MD5=$Md5Hash}; $Object | Select-Object -Property FileName,MD5 | Export-Csv -Path .\Whitelist.csv -Append }
If (!(Test-Path -Path $WhitelistPath))
{

    Throw "Please define the location of Whitelist.csv on line 5 of this script. A starting template has been included in the BTPS SecPack Sysmon directory"

}  # End If


If ($Null -eq $VirusTotalApiKey)
{

    Throw "GET A VIRUS TOTAL API KEY FROM https://www.virustotal.com/gui/join-us and place it in this script as the $VirusTotalApiKey variable on line 15"

}  # End If


$FinalResults = @()
$LogName = "Hash Validations"
$LogfileExists = Get-WinEvent -ListLog "Hash Validations" -ErrorAction SilentlyContinue
If (!($LogfileExists))
{

    New-EventLog -LogName $LogName -Source $LogName
    Limit-EventLog -LogName $LogName -OverflowAction OverWriteAsNeeded -MaximumSize 64KB

}  # End If


# Below 2 functions I stole from https://community.cisco.com/t5/security-blogs/powershell-using-virustotal-api-to-find-unknown-file-reputation/ba-p/3410001
Function Search-VirusTotal {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="`n[H] Enter a hash value that Virus Total is capable of comparing `n[E] EXAMPLE: F586835082F632DC8D9404D83BC16316")]  # End Parameter
            [String]$Hash
        )  # End param

    $Body = @{resource = $Hash; apikey = $VTApiKey}
    $VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $Body
    $AVScanFound = @()

    If ($VTReport.positives -gt 0)
    {

        ForEach($Scan in ($VTReport.scans | Get-Member -Type NoteProperty))
        {

            If ($Scan.Definition -Match "detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})")
            {
                If ($Matches.Detected -Eq "True")
                {

                    $AVScanFound += "{0}({1}) - {2}" -f $Scan.Name, $Matches.Version, $Matches.Result

                }  # End If

            }  # End If

        }  # End ForEach

    }  # End If

    New-Object –TypeName PSObject -Property ([ordered]@{
        MD5 = $VTReport.MD5
        SHA1 = $VTReport.SHA1
        SHA256 = $VTReport.SHA256
        VTLink = $VTReport.permalink
        VTReport = "$($VTReport.positives)/$($VTReport.total)"
        VTMessage = $VTReport.verbose_msg
        Engines = $AVScanFound
    })  # End New-Object

} # Function Search-VirusTotal


Function Get-VirusTotalReport {
    Param (
        [Parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="GET A VIRUS TOTAL API KEY FROM https://www.virustotal.com/gui/join-us and place it in the value below")]  # End Parameter
        [String]$VTApiKey,

        [Parameter(
            Mandatory=$True,
            Position=1,
            ValueFromPipeline=$True)]  # End Parameter
        [String[]] $Hash
    )  # End param

    $Hash | ForEach-Object { Search-VirusTotal -Hash $_ }  # End ForEach-Object

}  # End Function Get-VirusTotalReport


$Whitelist = Import-Csv -Path $WhitelistPath -Delimeter "," | Select-Object -Property "MD5"
$Events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1; StartTime=(Get-Date).AddHours(-1.2)}

$Obj = $Events | ForEach-Object {

            $Hash = $_ | Select-Object -ExpandProperty Message | Out-String | ForEach-Object { $_ -Split '\s{2}|:' | Where-Object { $_ -Match ',IMPHASH=' } | Select-Object -Unique }
            $ImpHash = $Hash | ForEach-Object { $_ -Replace "(?i)(?:.*?=)", "" }
            $Md5Hash = $Hash | ForEach-Object { $_.Trim() -Replace "[^,]*$", "" -Replace 'MD5=','' -Replace ',','' }

            If ($Whitelist.MD5 -NotContains $Md5Hash)
            {

                $VTResult = Get-VirusTotalReport -VTApiKey $VirusTotalApiKey -Hash $Md5Hash
                # The Free Virus Total API allows only 1 call every 15 seconds which is why we have Start-Sleep here
                Start-Sleep -Seconds 15

                If ($VTResult.VTReport[0] -gt 0)
                {

                    $Obj = New-Object -TypeName PSObject | Select-Object -Property VTInfoLink, MD5, SHA1, SHA256, IMPHASH, ProcessPath, MachineName, EventCreation, MoreInfo
                        $Obj.VTInfoLink = $VTResult.VTLink
                        $Obj.MD5 = $Md5Hash
                        $Obj.SHA1 = $VTResult.SHA1
                        $Obj.SHA256 = $VTResult.SHA256
                        $Obj.IMPHASH = $ImpHash
                        $Obj.ProcessPath = $_.Properties[4].Value
                        $Obj.MachineName = $_.MachineName
                        $Obj.EventCreation = $_.TimeCreated
                        $Obj.MoreInfo = $_.Message

                    $FinalResults += $Obj

                    Write-EventLog -LogName $LogName -Source $LogName -EntryType Information -EventId 4444 -Message ($Obj | Out-String)

                    $Obj

                }  # End If

            }  # End If

}  # End ForEach-Object

# If you want email alerts set up for this you can uncomment the below lines
#If ($FinalResults)
#{

#    Send-MailMessage -From FromEmail -To ToEmail -Subject "ALERT: Process not on Whitelist Has Been Run" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -UseSSL -Port 587  -Credential $Credential

#} # End If

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUcLWksjQDGGHLfIj+7X9qvv4
# QbCgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FJGsgvSPLY/mY4WwryUo+XAb+1WzMA0GCSqGSIb3DQEBAQUABIIBAAWNKg8kf596
# YEMWsWuoNOs5HDZxTNLRDAAB90XOcera5n4Bl/3Z7mx6aMPwiQTW1yT3QzkisYlj
# kYIQ6eg+hbYFwjCzAaE+TxpDsi5nuYmpciPdfJKVwuNYrtWvvhJUV7+o+6IzAsjv
# 9JWu1+u5ngTQou3SwuEO/g/AQcMmL87T8kk9wCxTQ8zmO0YWQPGSmTCUpxDB/fKX
# 30VQH7tTGswmj/jfylrpKhRw5ZV1xaP7DEI3T/MAbCD+jHEhzTKp249fFXDmbMAC
# 8OGxRV41u75NI8U2nFN1NjInmTFgKp976nWD0NBiDnUJIoaWGIpuRSSastu19k2W
# 1Wy6NfK/1Lo=
# SIG # End signature block
