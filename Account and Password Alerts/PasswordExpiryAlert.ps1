# Alerts IT admins and the users who have expiring or expired passwords. This needs to be run on a Domain Controller and works best when set up as a task

# Global variables
[Int32]$MaxPassAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
$RootDSE = Get-ADRootDSE -Server $env:USERDNSDOMAIN
$PasswordPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property minPwdAge, maxPwdAge, minPwdLength, pwdHistoryLength, pwdProperties 
$Policy =  $PasswordPolicy | Select @{n="PolicyType";e={"Password"}},`
                              @{n="maxPwdAge";e={"$($_.maxPwdAge / -864000000000) days"}},`
                              minPwdLength,`
                              pwdHistoryLength,`
                              @{n="pwdProperties";e={Switch ($_.pwdProperties) {
                                  0 {"Passwords can be simple and the administrator account cannot be locked out"}
                                  1 {"Passwords must be complex and the administrator account cannot be locked out"}
                                  8 {"Passwords can be simple, and the administrator account can be locked out"}
                                  9 {"Passwords must be complex, and the administrator account can be locked out"}
                                  Default {$_.pwdProperties}}}}
$PolicyString = "Max Password Age: " + ($Policy.maxPwdAge).ToString() + "`nPassword History: " + ($Policy.pwdHistoryLength).ToString() + "`nMinimum Password Length: " + ($Policy.minPwdLength).ToString()
[String]$EnvDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
[DateTime]$TodaysDate = Get-Date
[Array]$UserDetails = Get-ADUser -Filter { Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties * | Select-Object -Property "Displayname","Mail", @{l="ExpiryDate";e={$_.PasswordLastSet.AddDays($MaxPassAge)}}
[Array]$ExpiredPasswords = @()
[Array]$ExpiringSoon = @()
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

ForEach ($Users in $UserDetails) 
{

    $ExpirationDate = $Users.ExpiryDate 

    If ($ExpirationDate -ge $TodaysDate)
    {

        $ExpiredPasswords += $Users 

        $ToWhom = $Users.DisplayName

        $PreContent1 = "<Title>ALERT: Password Has Expired</Title>"
        $NoteLine1 = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss') from IT as a friendly reminder."
        $PostContent1 = "<br><p><font size='2'><i>$NoteLine1</i></font>"
        $MailBody1 = $Users | ConvertTo-Html -Head $Css -PostContent $PostContent1 -PreContent $PreContent1 -Body "Attention $ToWhom, <br><br>If you have received this email your sign in password has expired. <br><br>You can reset your password using the following link: <a href='https://account.activedirectory.windowsazure.com/ChangePassword.aspx?BrandContextID=O365&ruO365='>HERE</a> <br><br>If you are in the office on a company device press Ctrl + Alt + Del and click the Change Password button. If you are using the VPN you will need to connect to the VPN before changing your password. <br><br>$PolicyString<br><br><hr><br>" | Out-String
        
        # Alerts IT by sending an email
        $From1 = $Users.Mail | Out-String

        Try 
        {

            Send-MailMessage -From FromEmail -To $From1 -Subject "ACTION REQUIRED: Your Password Has Expired" -BodyAsHtml -Body $MailBody1 -SmtpServer UseSmtpServer -Priority High -UseSSL -Port 587 -Credential $Credential
        
        } # End Try

        Catch 
        {

            Send-MailMessage -From FromEmail -To $From1 -Subject "ACTION REQUIRED: Your Password Has Expired" -BodyAsHtml -Body $MailBody1 -SmtpServer UseSmtpServer -Priority High -UseSSL -Port 587 -Credential $Credential

            Send-MailMessage -From FromEmail -To ToEmail -Subject "Forward This Email Alert to $From1. Auto Send Failed" -BodyAsHtml -Body $MailBody1 -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential

        } # End Catch
  
    } # End if

    If (($TodaysDate -ge $ExpirationDate.AddDays(-15)) -and ($TodaysDate -le $ExpirationDate)) 
    {

        $ExpiringSoon += $Users 

        $ToWho = $Users.DisplayName

        $PreContent = "<Title>Password Expiring in 15 days or less</Title>"
        $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss') from IT as a friendly reminder."
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
        $MailBody = $Users | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "Attention $ToWho, <br><br>If you have received this email your password is expiring in 15 days or less. Reset your password before it expires. <br><br>$PolicyString<br><br>If you are on your home internet you can change your password by performing the following steps. <br><br>    <h4>Change Password From Home while connected to the VPN: </h4><strong>1.)</strong> Connect to the VPN. Enter your username and non-expired password. If you are not connected to a VPN or in the office your password change will not take effect and it will cause issues for you. <br>    <strong>2.)</strong> Press Ctrl+Alt+Del and select the 'Change Password' Button. <br>    <strong>3.)</strong> Enter a new password. Your new password needs to be at least 12 characters long and contain a lowercase letter, uppercase letter, and a number or special character. It can also not be one of the top 50 most commonly used passwords. <br><br>If you are changing your password from your desktop or a laptop that does not need to connect to the VPN because it is connected to DirectAccess, the previous rules apply with the execption of Step 1. Do not connect to the VPN on your desktop or a laptop already connected to DirectAccess as you are already on our network. <br><br><strong>NOTE:</strong> Be sure to sign into your laptop while you are in the office after you have changed your password. This is to ensure the laptop is aware your password has changed before you take it home. <br><br><strong>You are also able to change your password without connecting to the VPN at the following link: <a href='https://account.activedirectory.windowsazure.com/ChangePassword.aspx?BrandContextID=O365&ruO365='>HERE: Change Password Link</a> <br><hr><br>" | Out-String

        $From = $Users.Mail | Out-String

        Try 
        {

            Send-MailMessage -From FromEmail -To $From1 -Subject "ACTION REQUIRED: Your $EnvDomain Password is Expiring Soon" -BodyAsHtml -Body $MailBody -SmtpServer UseSmptServer -Priority Normal -UseSSL -Port 587 -Credential $Credential
        
        } # End Try

        Catch 
        {

            Send-MailMessage -From FromEmail -To $From1 -Subject "ACTION REUQIRED: Your $EnvDomain Password is Expiring Soon" -BodyAsHtml -Body $MailBody -SmtpServer UseSmptServer -Priority Normal -UseSSL -Port 587 -Credential $Credential

            Send-MailMessage -From FromEmail -To ToEmail -Subject "Forward This email to $From1. Auto Send Failed" -BodyAsHtml -Body $MailBody -SmtpServer UseSmptServer -UseSSL -Port 587 -Credential $Credential

        } # End Catch

    } # End Elseif

    Else 
    {

        Write-Output "[*] No passwords expiring in the next 14 days or less."

    } # End Else
 
} # End Foreach


If ($ExpiredPasswords) 
{

    $MBody1 = $ExpiredPasswords | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "FYI, <br><br>The below table contains info on the users who have received a password has expired notification.<br><br><hr><br>" | Out-String 
    Send-MailMessage -From FromEmail -To ToEmail -Subject "Users Whos Passwords Have Expired" -BodyAsHtml -Body $MBody1 -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential
  
} # End if
       

If ($ExpiringSoon)
{    
        
    $MBody = $ExpiringSoon | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "FYI, <br><br>The below table contains info on the users who have received a password exipring notification.<br><br><hr><br>" | Out-String 
    Send-MailMessage -From FromEmail -To ToEmail -Subject "Users Who Received Password Expiring Notifications" -BodyAsHtml -Body $MBody -SmtpServer UseSmptServer -UseSSL -Port 587 -Credential $Credential

} # End If

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9j3rtVmrLwq4wBnBdYuFork+
# irqgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FERFcY68q5RZX+0BGCRJdjDsB7wIMA0GCSqGSIb3DQEBAQUABIIBAHM7Xcnh8J+l
# ZX8+2m2TNnkLzA30/yvdZmTbWwcNlyElBeGR0CHlwPtD6w5qJlxNsyoSMyGArXLM
# iRU4XTR+Y7kTx3flziMD2OBh1nR4b7I0fufi9x756WSLk/sqBP+LzKpAwk7qM1ws
# ICAyacctctasfVydKhi1ST4GuQFqyyw4BFN8bso7VOKMUtwhWaWlxL6UobDipek3
# 7tnh787JGXYZ+MYU/u1TvRGs7zsUS0SfDf/eINOD3Ox542N2eZ5msNWPe/rVO5CM
# 3VtSNp52iYIqN3faky+5uAoPf4lNhD3fJRjgSTjBRTi9JmBojQQ6PmPqoDS/wz6m
# 5lHYHEcDTY4=
# SIG # End signature block
