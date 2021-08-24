# I built this off of a Microsoft suggested script. I will add the link if it is ever sent to me or I find it
#
# This script is used to remediate a compromised Office365 account by performing the Microsoft recommended actions.
#
# The following actions will be performed.
#
#    1.) Reset password (which kills the session).
#
#    2.) Remove mailbox delegates.
#
#    3.) Remove mailforwarding rules to external domains.
#
#    4.) Remove global mailforwarding property on mailbox.
#
#    5.) Set password complexity on the account to be high.
#
#    6.) Enable mailbox auditing.
#
#    7.) Produce Audit Log for the admin to review.

$Upn = Read-Host "What is the user's Email Address/UserPrincipalName Example: first.last@$env:USERDNSDOMAIN"
If ($Null -eq $Upn) {

    Throw "User UPN/email address was not defined was not defined. Ending script"

} # End If
Else {

    $SamAccountName = $Upn -Split "@"
    $TranscriptPath = "C:\Users\Public\Desktop\" + $SamAccountName[0] + "_RemediationTranscript_" + (Get-Date).ToString('MM-dd-yyyy') + ".txt"

    Start-Transcript -Path $TranscriptPath
    Write-Output "$Upn's account will have remediation actions applied to it.`nAn audit report will be saved to $TranscriptPath"

    Import-Module MSOnline
    Write-Verbose "Connecting to Exchange Online Remote Powershell Service"
    $ExoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential (Get-Credential -Message "Enter Global Admin Creds") -Authentication Basic -AllowRedirection

    If ($Null -ne $ExoSession) {

        Import-PSSession -Session $ExoSession

    } # End If
    Else {

        Output "[x] No EXO service set up for this account"

    } # End Else

    Write-Host "Connecting to EOP Powershell Service" -ForegroundColor Cyan
    $EopSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $AdminCredential -Authentication Basic -AllowRedirection

    If ($Null -ne $EopSession) {

        Import-PSSession -Session $EopSession -AllowClobber

    } # End If
    Else {

        Write-Output "[x] No EOP service set up for this account"

    } # End Else

    Connect-MsolService -Credential $AdminCredential
    [Reflection.Assembly]::LoadWithPartialName("System.Web")

# BELOW THIS LINE CREATES THE FUNCTIONS------------------------------------------------------------------------

Function Reset-Password($Upn) {

    $NewPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))
    Set-MsolUserPassword –UserPrincipalName $Upn –NewPassword $NewPassword -ForceChangePassword $True

    Write-Host "Password for the user $Upn was changed to $NewPassword. Make sure you record this and share with the user, or be ready to reset the password again. They will have to reset their password on the next logon." -ForegroundColor Cyan
    Set-MsolUser -UserPrincipalName $Upn -StrongPasswordRequired $True

} # End Function Reset-Password



Function Enable-MailboxAuditing($Upn) {

    Write-Host "Mailbox auditing for user is being enabled..."
    Set-Mailbox $Upn -AuditEnabled $True -AuditLogAgeLimit 365

    Write-Host "Current auditing configuration."
    Get-Mailbox -Identity $Upn | Select-Object -Property Name, AuditEnabled, AuditLogAgeLimit

} # End Functgion Enable-MailboxAuditing



Function Remove-MailboxDelegates($Upn) {

    Write-Host "Removing Mailbox Delegate Permissions for the affected user $upn." -ForegroundColor Cyan
    $MailboxDelegates = Get-MailboxPermission -Identity $Upn | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}

    Get-MailboxPermission -Identity $Upn | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}
    ForEach ($Delegate in $MailboxDelegates) {

        Remove-MailboxPermission -Identity $Upn -User $Delegate.User -AccessRights $Delegate.AccessRights -InheritanceType All -Confirm:$False

    } # End ForEach

} # End Function Remove-MailboxDelegates



Function Disable-MailforwardingRulesToExternalDomains($Upn) {

    Write-Host "Disabling mailforwarding rules to external domains for the affected user $Upn."
    Write-Host "Found the following rules that forward or redirect mail to other accounts: "

    Get-InboxRule -Mailbox $Upn | Select-Object -Property Name, Description, Enabled, Priority, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, SendTextMessageNotificationTo | Where-Object {(($_.Enabled -eq $True) -and (($_.ForwardTo -ne $Null) -or ($_.ForwardAsAttachmentTo -ne $Null) -or ($_.RedirectTo -ne $Null) -or ($_.SendTextMessageNotificationTo -ne $Null)))} | Format-Table
    Get-InboxRule -Mailbox $Upn | Where-Object {(($_.Enabled -eq $true) -and (($_.ForwardTo -ne $Null) -or ($_.ForwardAsAttachmentTo -ne $Null) -or ($_.RedirectTo -ne $Null) -or ($_.SendTextMessageNotificationTo -ne $Null)))} | Disable-InboxRule -Confirm:$False
    Write-Output "Completed disabling of rules being forwarded to outside domains"

} # Disable Disable-MailforwardingRulesToExternalDomains



Function Remove-MailboxForwarding($Upn) {

    Write-Output "Removing Mailbox Forwarding configurations for the affected user $Upn. Current configuration is:"
    Get-Mailbox -Identity $Upn | Select-Object -Property Name, DeliverToMailboxAndForward, ForwardingSmtpAddress
    Set-Mailbox -Identity $Upn -DeliverToMailboxAndForward $False -ForwardingSmtpAddress $Null

    Write-Host "Mailbox forwarding removal completed. Current configuration is:"
    Get-Mailbox -Identity $Upn | Select-Object -Property Name, DeliverToMailboxAndForward, ForwardingSmtpAddress

} # End Function Remove-MailboxForwarding



Function Get-AuditLog ($Upn) {

    Write-Host "$Upn account has been remediated. There may be things missed. Review the audit transcript for this user to be super-sure you've got everything." -ForegroundColor Red
    $UserName = $Upn -split "@"
    $AuditLogPath = ".\" + $UserName[0] + "AuditLog" + (Get-Date).ToString('MM-dd-yyyy') + ".csv"
    $StartDate = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
    $EndDate = (Get-Date).ToString('MM/dd/yyyy')
    $Results = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $Upn
    $Results | Export-Csv -Path $AuditLogPath

    Write-Host "Log of this command can be found here: $AuditLogPath. You can also review the activity below." -ForegroundColor Green
    $Results | Format-Table

} # End Function Get-AuditLog




# BELOW THIS LINE EXECUTES THE ABOVE CREATED FUNCTIONS---------------------------------------------------------------------------

    Reset-Password $Upn
    Enable-MailboxAuditing $Upn
    Remove-MailboxDelegates $Upn
    Disable-MailforwardingRulesToExternalDomains $Upn
    Remove-MailboxForwarding $Upn

    Get-AuditLog $Upn
    Stop-Transcript

} # End Else

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUb4bXGRjwbFyvF1NJ3wTXd3Uz
# 3N+gggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FPGFCjn7Evq9R47r2Y0qyvSlgLUaMA0GCSqGSIb3DQEBAQUABIIBADhqGfJioVa/
# kMrFfi2KibhE728ftFQJVq3dZ8H+iX+62lgr1ZbpLzZvKHB0AvuvGNQmKKwJuPx9
# iJpiQWOLigaGN6hgP498C0RqHEBAOUinKwYqXo1XU5FSgPtjnPbuSYpysxXrFVUD
# FTHLPl/fwALY/DkCEC1tCOdf/GBHzaZ4is0oIiz7Xpj8LE6gDnbBEOVcx28kAdoC
# i4O6MnmAEnIGPDrmTDQoDDuXrZ/BV65g0W0I5PrxyEE5AzOG/KzVfspclyiwHz4w
# P2I5/ri1deAYEAMp6YAcjFXJbaK3irMgatiFKqiwAnqu01hV3BqF2LSMYgADYx0q
# 7WB5D9HBiU8=
# SIG # End signature block
