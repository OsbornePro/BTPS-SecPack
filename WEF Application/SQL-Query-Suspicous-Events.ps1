# Email Variables
$To = ""
$From = ""
$SmtpServer = ""

# Applications that are filtered from triggering alerts
# DEFENDER : C:\ProgramData\Microsoft\Windows Defender\Definition Updates\
# SYSMON   : C:\Windows\SysmonDrv.sys C:\Windows\Sysmon.exe \SystemRoot\SysmonDrv.sys
# FIREFOX  : C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe
# ONEDRIVE : C:\Program Files (x86)\Microsoft OneDrive\20.124.0621.0006\FileSyncHelper.exe C:\Program Files (x86)\Microsoft OneDrive\%\OneDriveUpdaterService.exe
# EDGE     : C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe C:\Program Files (x86)\Microsoft\Edge\Application\%\elevation_service.exe
# ADOBE    : C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGSService.exe C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGMService.exe C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ElevationManager\AdobeUpdateService.exe C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe
# CHROME   : C:\Program Files (x86)\Google\Update\GoogleUpdate.exe C:\Program Files (x86)\Google\Chrome\Application\77.0.3865.120\elevation_service.exe

$FinalResults= @()
$Date = Get-Date 
$ConnectionString = "Server=(localdb);Database=EventCollections;Integrated Security=True;Connect Timeout=30"

# SQL Queries to discover suspicious activity
$ClearedEventLog = "Id=1102"
$PasswordChange = "Id=4723 OR Id = 4724"
$UserAddedToAdminGroup = "Id=4732 OR Id=4756 OR Id=4728"
$UserRemovedFromAdminGroup = "Id=4733 OR Id=4757 OR Id=4729"
$UserAccountCreated = "Id=4720"
$UserAccountDeleted = "Id=4726"
$NewServiceInstalled = "Id=7045 AND Message NOT LIKE '%C:\Program Files (x86)\Common Files\Adobe\Adobe Desktop Common\ElevationManager\AdobeUpdateService.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGMService.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient\AGSService.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Google\Chrome\Application\77.0.3865.120\elevation_service.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Google\Update\GoogleUpdate.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Microsoft\Edge\Application\%\elevation_service.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Microsoft OneDrive\%\OneDriveUpdaterService.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Microsoft OneDrive\20.124.0621.0006\FileSyncHelper.exe%' AND Message NOT LIKE '%C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe%' AND Message NOT LIKE '%C:\Windows\SysmonDrv.sys%' AND Message NOT LIKE '%C:\Windows\Sysmon.exe%' AND Message NOT LIKE '%\SystemRoot\SysmonDrv.sys%' AND Message NOT LIKE '%C:\ProgramData\Microsoft\Windows Defender\Definition Updates\%'"
$UserAccountLocked = "Id=4740"
$UserAccountUnlocked = "Id=4767"
$SpecialPrivilegeAssigned = "Id=4672 AND Message NOT LIKE '%paessler%' AND Message NOT LIKE '%dnsdynamic%' AND Message NOT LIKE '%nessus.admin%'"
$ReplayAttack = "Id=4649"
$MaliciousIPCheck = "Id=1 OR Id=2"

# This is an array of SQL Commands to execute
$Sqls = $MaliciousIPCheck,$ClearedEventLog,$PasswordChange,$UserAddedToAdminGroup,$UserRemovedFromAdminGroup,$UserAccountCreated,$UserAccountDeleted,$NewServiceInstalled,$UserAccountLocked,$UserAccountUnlocked,$SpecialPrivilegeAssigned,$ReplayAttack

Function Find-NewlyCreatedLocalAccounts {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage="Enter the connection string to connect to a SQL Server")]  # End Parameter
            [String]$ConnectionString, 
            
            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter a MSSQL Query to execute")]  # End Parameter
            [String]$SqlCommand)  # End param

BEGIN 
{

    Write-Verbose "Creating connection to SQL database and SQL command"

    $Connection = New-Object -TypeName System.Data.SqlClient.SQLConnection($ConnectionString)
    $Connection.Open()

    $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand($SqlCommand, $Connection)
    $Adapter = New-Object -TypeName System.Data.SqlClient.SqlDataAdapter -ArgumentList $Command
    $Dataset = New-Object -TypeName System.Data.DataSet

}  # End BEGIN
PROCESS
{

    Write-Verbose "Executing SQL Command: $SqlCommand"

    $Adapter.Fill($Dataset) | Out-Null
    $Connection.Close()

}  # End PROCESS
END
{

    $Dataset.Tables[0].Rows

}  # End END

}  # End Function Find-NewlyCreatedLocalAccounts


ForEach ($Sql in $Sqls)
{

    $SqlCommand = "DECLARE @CurHour DATETIME, @PrevHour DATETIME; SET @CurHour = DATEADD(hour, DATEDIFF(hour,'20110101',CURRENT_TIMESTAMP),'20110101'); SET @PrevHour = DATEADD(hour,-1, @CurHour); SELECT MachineName,TimeCreated,Id,Message FROM dbo.GeneralEvents WHERE TimeCreated >= @PrevHour and TimeCreated < @CurHour AND $Sql ORDER BY TimeCreated DESC"
    
    $Results = Find-NewlyCreatedLocalAccounts -ConnectionString $ConnectionString -SqlCommand $SqlCommand -Verbose  
    
    If ($Results) 
    {
        
        Switch ($Sql)
        {

            $ClearedEventLog {$Significance = 'Event Log Cleared'}
            $PasswordChange {$Significance = 'Password Change Attempt'}
            $UserAddedToAdminGroup {$Significance = 'User Added to Privileged Group'}
            $UserRemovedFromAdminGroup {$Significance = 'User Removed from Privileged Group'}
            $UserAccountCreated {$Significance = 'User Account Created'}
            $UserAccountDeleted {$Significance = 'User Account Deleted'}
            $NewServiceInstalled {$Significance = 'New Service Installed'}
            $UserAccountLocked {$Significance = 'Account Locked Out'}
            $UserAccountUnlocked {$Significance = 'Account Unlocked'}
            $SpecialPrivilegeAssigned {$Significance = 'Special Privileges Assigned'}
            $ReplayAttack {$Significance = 'Replay Attack Detected'}
            $MaliciousIPCheck { $Significance = "Connection to an IP that is on a blacklist or a domain less than 2 years old"}

        }  # End Switch

        $Results | Add-Member -NotePropertyName "Significance" -NotePropertyValue "$Significance"

        $FinalResults += $Results | Select-Object -Property TimeCreated,MachineName,Significance,Message,ID

        Remove-Variable Results,Significance

    }  # End If

}  # End ForEach

If ($FinalResults)
{

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
    $PreContent = "<Title>Suspicous Events</Title>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
    $MailBody = $FinalResults | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains suspicous events that were triggered<br><br><hr><br><br>" | Out-String

    Send-MailMessage -From FromEmail -To ToEmail -Subject "SUSPICIOUS EVENT TRIGGERED" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587
    
}  # End If 

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQvTqfs2P+xegxaLPelO323vm
# Cmegggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FNfh8z0ZtGDoLwNycIhnqJz6sCjnMA0GCSqGSIb3DQEBAQUABIIBAHcFsLi3ZcFg
# qoJnXIdVz+S0FFIGjEJVs45/wsoRzL/WgkSBLQrpK8EYodGuN9Rwdy9M3i4UWBsV
# XW+XM7KBTsiD3Ccz1SIjJX54ZFpnfV3bcUPfLbBB+5rI+1WPo/c29zkDFVeaMyI+
# r5QYSU+Z9CC+e9nAxctzB9lWugvEYiwqThxIQgLKlmm6aiJMTiznD25CFT1rNeSs
# Ul7ZqCVbOnIrdHduD6ZHTeZCaq1igNZJQ2cntXObTwhlxSjYDJoxul3yYEWAEe96
# ZamD35iK6cDQ2ohAaWZFaG1iAo4+X7Fh/21BegdY2Q5X+Bz73hNCeiJ9Pf5Ii1d4
# vcJrqb7cocY=
# SIG # End signature block
