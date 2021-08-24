<#
.SYNOPSIS
This cmdlet is for uninstalling a Windows Update. This can remove multiple hot fixes and it can remove hot fixes from an array of remote computers.


.DESCRIPTION
Remove-WindowsUpdate is a cmdlet that is used to remove a speficied Windows Update or Updates from a local computer or a remote host or hosts. A list of computer names can be piped to this function by property name.


.PARAMETER HotFixID
Specifies the hotfix IDs that this cmdlet gets.

.PARAMETER ComputerName
Specifies a remote computer. The default is the local computer. Type the NetBIOS name, an Internet Protocol (IP) address, or a fully qualified domain name (FQDN) of a remote computer.

.PARAMETER Restart 
Specifies whether or not the remote computer should be restarted after the patch is removed.


.EXAMPLE
Remove-WindowsUpdate -HotFixID "4556799"
# This examples uninstalls 4556799 from the local computer if it is installed.

.EXAMPLE
Remove-WindowsUpdate "KB4556799"
# This examples also uninstalls HotFix KB4556799 from the local computer.

.EXAMPLE
Remove-WindowsUpdate -HotFixID "KB4556799" -ComputerName 10.10.10.120 -Restart
# This examples uninstalls HotFix KB4556799 from a remote computer at 10.10.10.120 and if a restart is needed allows it to restart.

.EXAMPLE
Remove-WindowsUpdate "KB4556799" 10.10.10.120
# This examples also uninstalls HotFix KB4556799 from a remote computer at 10.10.10.120.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String
You can pipe computer names to this cmdlet..
In Windows PowerShell 2.0, the ComputerName parameter takes input from the pipeline only by property name. In
Windows PowerShell 3.0, the ComputerName parameter takes input from the pipeline by value.


.OUTPUTS
None, System.Management.Automation.RemotingJob
This cmdlet returns a job object, if you specify the AsJob parameter. Otherwise, it does not generate any output.


.LINK
https://osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Remove-WindowsUpdate {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage="Enter the Windows Update KB number(s) you wish to uninstall. Separate multiple values with a comma.`nExample: KB4556799','KB4556798' (4556799 is also acceptable) `n")]  # End Paramater
            [String[]]$HotFixID,

            [Parameter(
                Mandatory=$False,
                Position=1,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter the name or names of the remote compute you wish to uninstall. Separate multiple values with a comma. `nExample: 'Comp1.domain.com','Comp2','10.10.10.123'`n")]  # End Paramater
            [ValidateNotNullOrEmpty()]
            [String[]]$ComputerName,

            [Parameter(
                Mandatory=$False)]
            [switch][bool]$Restart
        )  # End param

BEGIN {

    If ($ComputerName) {

        For ($i = 0; $i -lt $ComputerName.Count ; $i++) {

            ForEach ($Computer in $ComputerName) {

                Write-Verbose "[*] Testing specified $Computer is reachable"
                If (Test-Connection -ComputerName $Computer -Quiet -ErrorAction Inquire) {

                    Write-Verbose "[*] $Computer is reachable"
                    Try {

                        If ($Null -eq $Cred) {

                            $Cred = Get-Credential -Message "Administrator Credentials are required to execute commands on remote hosts" -Username ($env:USERNAME + "@" + ((Get-WmiObject Win32_ComputerSystem).Domain))

                        }  # End If

                        New-Variable -Name "Session$i" -Value (New-PsSession -ComputerName $Computer -Credential $Cred -Name $Computer -EnableNetworkAccess -Port 5986 -UseSSL)

                    }  # End Try
                    Catch {

                        Write-Verbose "[*] Skipping certificate validation checks to create an encrypted session with the remote host."

                        New-Variable -Name "Session$i" -Value (New-PsSession -ComputerName $Computer -Credential $Cred -EnableNetworkAccess -Port 5986 -UseSSL -SessionOption (New-PsSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck))

                    }  # End Catch

                }  # End If

            }  # End ForEach

        }  # End For

    }  # End If

}  # End BEGIN
PROCESS {

    If ($ComputerName) {
        
        For ($n = 0; $n -lt $ComputerName.Count; $n++) {

            ForEach ($C in $ComputerName) {

                Write-Verbose "[*] Starting connection to $C"
                Invoke-Command -Session (Get-Variable -Name "Session$n").Value -ArgumentList $HotFixID -ScriptBlock {
                    param([array]$HotFixID)

                    Write-Output "[*] Getting list of installed patches"
                    $PatchList = Get-CimInstance -ClassName "Win32_QuickFixEngineering" -Namespace "root\cimv2"

                    ForEach ($HotFix in $HotFixID) {

                        $Patch = $PatchList | Where-Object { $_.HotFixID -like "$HotFix" }
                        Write-Output "[*] $Patch will be removed from $env:COMPUTERNAME"

                        If (!($Patch)) {

                            Write-Output "[!] The Windows Update KB number you defined is not installed on $env:COMPUTERNAME. Below is a table of installed patches: "
                            Remove-Variable -Name "Patch"

                            $PatchList

                        }  # End If
                        Else {

                            Write-Output "[*] $HotFix is installed on $env:COMPUTERNAME, continuing uninstallation"
                            $KBNumber = $Patch.HotfixId.Replace("KB", "") | Out-String

                            If ($Restart.IsPresent) {

                                Write-Output "[*] Restart switch parameter is defined. You will be prompted to restart."
                                cmd /c wusa /uninstall /kb:$KBNumber /promptrestart /log

                            }  # End If
                            Else {

                                cmd /c wusa /uninstall /kb:$KBNumber /norestart /log

                            }  # End Else

                            While (@(Get-Process wusa -ErrorAction SilentlyContinue).Count -ne 0) {

                                Start-Sleep -Seconds 10
                                Write-Output "Waiting for update removal to finish. Please wait..."

                            }  # End While

                        }  # End Else

                    }  # End ForEach

                }  # End Invoke-Command

                Write-Verbose "[*] Finished removing updates from $C"

            }  # End ForEach

        }  # End For

    }  # End If
    Else {

        Write-Verbose "[*] Getting list of installed patches on $env:COMPUTERNAME"
        $PatchList = Get-CimInstance -ClassName "Win32_QuickFixEngineering" -Namespace "root\cimv2"

        ForEach ($HotFix in $HotFixID) {

            $Patch = $PatchList | Where-Object { $_.HotFixID -like "$HotFix" }
            If (!($Patch)) {

                Write-Output "[!] The Windows Update KB number you defined is not installed on $env:COMPUTERNAME. Below is a table of installed patches: "
                Remove-Variable -Name "Patch"

                $PatchList

            }  # End If
            Else {

                $KBNumber = $Patch.HotfixId.Replace("KB", "") | Out-String
                If ($Restart.IsPresent) {

                    Write-Output "[*] Restart switch parameter is defined. You will be prompted to restart."

                    cmd /c wusa /uninstall /kb:$KBNumber /norestart /log

                }  # End If
                Else {

                    cmd /c wusa /uninstall /kb:$KBNumber /norestart /log

                }  # End Else

                While (@(Get-Process wusa -ErrorAction SilentlyContinue).Count -ne 0) {

                    Start-Sleep -Seconds 10
                    Write-Output "[*] Waiting for update removal to finish. Please wait..."

                }  # End While

                Write-Output "[*] Update removal has completed"

            }  # End Else

        }  # End ForEach

    }  # End Else

}  # End PROCESS
END {

    If (Get-PsSession) {

        Write-Verbose "[*] Closing connection to remote computers."
        Remove-PsSession *

    }  # End If

}  # End END

}  # End Function Remove-WindowsUpdate

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUytP/T8rcN8lQ4LaK5j7nIrPR
# rACgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FOKZ8j1T0R96/TsGIz/Y9E0txvZMMA0GCSqGSIb3DQEBAQUABIIBAJP59OLOGkzj
# b81+oRbCqX1TT2rxj9s2KuevpHstjcz+IjsqzrLnwBbqLOUULvf7168Ak7Rqqnop
# YlBvopsJ0+k13j0uEDsWHkW/x8/cfL/cJQV+k/Agwpv+0wUHHkRo8NxObfoiK7PT
# obGeQpFZ85kMbupk9Pxs9EWlEYGWgmHwyiCgB269j9hfPJQ+dAASvT/fJrhxu3AF
# 7Cmg0GqECo1S4hm+If9yAvZ0to2LfeM0tGnZIkokQHq7YuxymL53+/WhL9TFR1qR
# Aa0/q7VRbNrvgPH+ZXc7U6ga2XJiKev1qysAVpHtxx364wO0lRaJ4pV0fy6RQfjx
# Sw1TRYwEi1A=
# SIG # End signature block
