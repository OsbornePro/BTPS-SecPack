# This script is meant to simplify the install of Sysmon according the BTPS Sec Pack https://www.btps-secpack.com/
$DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PrimaryDC = ($DomainObj.PdcRoleOwner).Name
$Domain = $DomainObj.Forest.Name
If ($PrimaryDC -ne "$env:COMPUTERNAME.$Domain") {

    Throw "[x] This script is required to run on $PrimaryDC, your primary domain controller in order to push out sysmon through Group Polciy"

}  # End If


Write-Output "[*] Ensuring PowerShell uses TLSv1.2 for downloads"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


Write-Output "[*] Downloading the Sysinternals Suite tool Sysmon from Microsoft at https://download.sysinternals.com/files/Sysmon.zip"
(New-Object -TypeName System.Net.WebClient).downloadFile("https://download.sysinternals.com/files/Sysmon.zip", "$env:USERPROFILE\Downloads\Sysmon.zip")


Write-Output "[*] Unzipping the download Sysmon.zip file to your C:\Sysmon"
Expand-Archive -Path "$env:USERPROFILE\Downloads\Sysmon.zip" -Destination "C:\Sysmon\"
If (!(Test-Path -Path "C:\Sysmon\Sysmon.exe")) {

    Throw "Failed to extract the sysmon.zip file to C:\Sysmon. Ensure you have the appropriate permissions to download to C:\"

}  # End If


Write-Output "[*] Downloading the sysmon.xml configuration file from the B.T.P.S. Security Package Github repository"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/sysmon.xml" -OutFile "C:\Sysmon\sysmon.xml"

Write-Output "[*] Downloading the sysmon.bat install file from the B.T.P.S. Security Package Github repositroy"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/sysmon.bat" -OutFile "C:\Sysmon\sysmon.bat"

Write-Output "[*] Modifying sysmon.bat to contain appropriate values for your environment"
(Get-Content -Path "C:\Sysmon\sysmon.bat") -Replace "DomainControllerHostname", "$PrimaryDC" -Replace "NETLOGON", "Sysmon" | Set-Content -Path "C:\Sysmon\sysmon.bat"

$Answer1 = Read-Host -Prompt "Would you like to add the Malicious IP checker to devices in your environment as well? This provides extra checks against domains and IP addresses collected by Sysmon logged network connections. [y/N]"
If ($Answer1 -like "y*") {

    Write-Output "[*] Downloading the Task Template for Malicious IP checker and the Script it executes"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/MaliciousIPChecker.xml" -OutFile "C:\Sysmon\MaliciousIPChecker.xml"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/MaliciousIPChecker.ps1" -OutFile "C:\Sysmon\MaliciousIPChecker.ps1"

}  # End If

$Answer2 = Read-Host -Prompt "[*] Would you like to download the Process Hash Validator as well? This script and task is used to perform extra analysis on process logs collected by Sysmon. [y/N]"
If ($Answer2 -like "y*") {

    Write-Output "[*] Downloading Process Hash Validator task and the script that gets executed"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/HashValidator.xml" -OutFile "C:\Sysmon\HashValidator.xml"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/HashValidator.ps1" -OutFile "C:\Sysmon\HashValidator.ps1"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/tobor88/BTPS-SecPack/master/Sysmon/Whitelist.csv" -OutFile "C:\Sysmon\Whitelist.csv"

    $VTAnswer = Read-Host -Prompt "Do you have a Virus Total API Key? [y/N]"
    If ($VTAnswer -notlike "y*") {

        Start-Process -FilePath "https://www.virustotal.com/gui/join-us"
        Pause

    }  # End Else
    $VTAPIKey = Read-Host -Prompt "Paste your Virus Total API Key here: "
    ((Get-Content -Path "C:\Sysmon\HashValidator.ps1") -Replace "$VirusTotalApiKey = ''","$VirusTotalApiKey = '$VTAPIKey'") | Set-Content -Path "C:\sysmon\HashValidator.ps1"

}  # End If

Write-Output "[*] Turning C:\Sysmon into a Network Share for use with pushing out Sysmon logging to domain joined devices"
New-SmbShare -Name "Sysmon" -Path "C:\Sysmon" -FullAccess "$Domain\Domain Admins","Administrators" -ChangeAccess "Users"

Write-Output '[*] Disabling SMB version 1'
Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

Write-Output '[*] Enabling SMBv2 and SMBv3'
Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force


Write-Output "[*] Creating a GPO called 'Settings Sysmon' for you to configure \\$PrimaryDC\Sysmon\sysmon.bat as a startup script. I am not able to configure the rest through PowerShell unfortunately. The settings for this is easy however"
New-GPO -Name "Settings Sysmon" -Domain $Domain -Comment "Group policy object used to get sysmon installed on domain joined devices"

Write-Output "INSTRUCTIONS ON CONFIGURING SYSMON STARTUP SCRIPT IN GPO"
Write-Output "  1.) In Server Manager on $PrimaryDC, go to Tools > 'Group Policy Management'"
Write-Output "  2.) 'Group Policy Management' Window will open. Expand 'Forest: $Domain' > Expand 'Domains' > Expand '$Domain' > Expand 'Group Policy Objects' > Right click on 'Settings Sysmon' and select Edit"
Write-Output "  3.) Navigate the dropdowns from 'Computer Management' > 'Policies' > 'Windows Settings' > 'Scripts' > and Double Click 'Startup' to open the 'Startup Properties' Window"
Write-Output "  4.) With the 'Scripts' tab selected click the 'Add' button."
Write-Output "  5.) In the 'Script Name' text box enter your network share path to sysmon.bat which is most likely '\\$PrimaryDC.$Domain\Sysmon\sysmon.bat'. Leave the 'Parameters' text box blank"
Write-Output "  6.) Click OK and then click OK again. This completes our GPO for Sysmon"

Pause

Write-Host "For images and more info on how to configure Group Policy for Malicious IP Checker and Process Hash Validator visit https://btps-secpack.com/sysmon-setup"

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJnMM/drfe9VIPXm7kyhiWggF
# B5Ogggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FKKWwA2mXzlJnNwCk1H8JQLFi05SMA0GCSqGSIb3DQEBAQUABIIBAKUyLxsRwI3D
# tzKPQAhdbYbaeyDAHMrtLwVdNWSzAVZ7udiSnCZMmu2ahDzUpmjl2064IqS8g8++
# WtyihF4MHIXsEhkNNIcbpmqMRLZ+r0j14LHmjLw+Dc5vnR/ZECeuO4q1Ci1fEer/
# iL3VXRC4sA0xsVTZHQfq18DSQGsCL0hLOlCG0FImx126DKjc3Tw729IGqZHvAKdu
# ZNqx7UPuMDsuA6aA+bwJ57aqL7HKwtQed81h5LojUcqSfuK7YXrq4Upp+nrt7DrD
# LSpEyG/ARKm32l29n9uCrM2Qp6KtG582ZQJ63+/MuzlS9bre09QwwAnpSuoGYEWG
# xzPTlllYvS0=
# SIG # End signature block
