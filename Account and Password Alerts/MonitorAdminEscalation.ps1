# This alert was meant to be used in cases where a user in your environment who should not have administrator credentials was given administrator credentials. It will alert you whenever their credentials are used to execute a process with higher privilege

$MonitorAdmin = ''

Get-Credential | Export-CliXml -Path "${env:\userprofile}\MonitorAdmin.Cred"
$Cred = Import-CliXml -Path "${env:\userprofile}\MonitorAdmin.Cred"

Write-Verbose "Building queries"
$XMLConsent = "<QueryList>
    <Query Id='0' Path='Security'>
        <Select Path='Security'>
            *[System[(EventID=4648) and TimeCreated[timediff(@SystemTime) &lt;= 300000]] and EventData[Data[@Name='ProcessName']='C:\Windows\System32\consent.exe'] and EventData[Data[@Name='TargetUserName']=`'$MonitorAdmin`']]
        </Select>
    </Query>
</QueryList>"

$XMLAuthAsUser = "<QueryList>
    <Query Id='0' Path='Security'>
        <Select Path='Security'>
            *[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= 300000]] and EventData[Data[@Name='LogonType']='11'] and EventData[Data[@Name='ProcessName']='C:\Windows\System32\consent.exe'] and EventData[Data[@Name='TargetUserName']=`'$MonitorAdmin`']]
        </Select>
    </Query>
</QueryList>"

$XMLProcInfo = "<QueryList>
    <Query Id='0' Path='Security'>
        <Select Path='Security'>
            *[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) &lt;= 300000]] and EventData[Data[@Name='TargetUserName']=`"$MonitorAdmin`"]]
        </Select>
    </Query>
</QueryList>"


If (Get-WinEvent -FilterXml $XMLConsent | Select-Object -Property * -First 1)
{

    Write-Verbose "Admin credentials have been used to escalate privileges"

    Write-Verbose "Verifying password was entered correctly"
    If (Get-WinEvent -FilterXML $XMLAuthAsUser | Select-Object -Property * -First 1)
    {

        Write-Verbose "Administrator credentials were entered successfully"

        Write-Verbose "Correlating Process with successful logon"
        $ProcessInfo = Get-WinEvent -FilterXml $XMLProcInfo | Select-Object -Property * -First 1

        If ($ProcessInfo)
        {

            $Results = $ProcessInfo | ForEach-Object {

                $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, AdminUser, SID, MachineName, Process, Date, Message
                $Obj.EventID = $_.Id
                $Obj.AdminUser = $_.Properties[10].Value
                $Obj.SID = $_.Properties[9].Value
                $Obj.MachineName = $_.MachineName
                $Obj.Process = $_.Properties[5].Value
                $Obj.Date = $_.TimeCreated
                $Obj.Message = "A new process was started. It has been executed using verified Administrator credentials"
                
                $Obj
    
            }  # End ForEach-Object
    
            If ($Results)
            {
            
                $Admin = $Results.AdminUser
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
            
                $PreContent = "<Title>$Admin Used His Admin Credentials</Title>"
                $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
                $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
                $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on the process that was created after $Admin executed it successfully using administrator credentials.<br><br><hr><br><br>" | Out-String
            
               Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: $Admin Executed and Eleveated Process" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -UseSsl -Port 587 -Credential $Credential
            
            }  # End If
            
        }  # End If

    }  # End If

}  # End If

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGRb7gldrMFUOqLgbw3EETX4N
# vRigggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FBa00TPQDYr/oSn4LpoPLgTDDGtwMA0GCSqGSIb3DQEBAQUABIIBAJ7Gj4rN0EwF
# CL0uHovfYgX7zocLqRg5L1BP8AnoHhmK4+yOLl6AWPRhkkri8n7UtY+P53pQv4a1
# mBw1OCyzXX2x5JNbHvapB8xFzJFvnDM/Z70aXICclkTJZezDv4aKxW9GBQYtEar3
# vrglCF5L7n0m2uFuPxI0S8JN/JvQYHFwvHQj/vi7f7wkgNg4XQrxWF0bLDhDm6YL
# QGxDPIKd7Yx5K+CpzEXhcrGd8wCgFLzw+VIjqTRHpktP89zfGeXah44ET1h0Yku6
# X0gGDseLPuoHOF6RF5wgzgiHGHZQ6tE9X/zOt9bDoCzDV7AMIJUrkm1h5gfKkcec
# SoFK+TESX5k=
# SIG # End signature block
