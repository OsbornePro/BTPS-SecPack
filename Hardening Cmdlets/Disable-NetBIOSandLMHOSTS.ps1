<#
.SYNOPSIS
This cmdlet is used to disable NetBIOS on a local or remote device(s). This prevents the ability of an attacker to capture password hashes with tools such as Responder


.DESCRIPTION
This cmdlet modifies the registry values HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip NetbiosOptions to the value 2 which disables NetBIOS
SetTcpopNetbios option:
0 - Use NetBIOS setting from the DHCP server
1 - Enable NetBIOS over TCP/IP
2 - Disable NetBIOS over TCP/IP


.PARAMETER ComputerName
This parameter defines the remote device you wish to disable NetBIOS on

.PARAMETER UseSSL
This parameter indicates you wish to use WinRM over HTTPS when executing commands on the remote devices

.PARAMETER Undo
This switch parameter indicates you wish to re-enable NetBIOS on a local or remote machine you accidently or incorrectly disabled NetBIOS on

.PARAMETER UseDHCPNetBIOSSetting
This switch parameter indicates you wish to use the DHCP servers settings to define whether NetBIOS is enabled or not

.PARAMETER EnableLMHOSTS
This switch parameter can be used to enable LMHOST usage instead of disabling it


.EXAMPLE
Disable-NetBIOS
# This example disables NetBIOS on all interfaces on the local machine

.EXAMPLE
Disable-NetBIOS -Undo
# This example re-enables NetBIOS on all interfaces on the local machine

.EXAMPLE
Disable-NetBIOS -UseDHCPNetBIOSSetting
# This example uses DHCP settings to determine the NetBIOS settings on all interfaces on the local machine

.EXAMPLE
Disable-NetBIOS -ComputerName 'DC01','DC02.domain.com'
# This example disables NetBIOS on all interfaces on DC01 and DC02.domain.com using WinRM

.EXAMPLE
Disable-NetBIOS -ComputerName 'DC01','DC02.domain.com' -UseSSL -Undo
# This example re-enables NetBIOS on all interfaces on DC01 and DC02.domain.com using WinRM over HTTPS


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com
Also as a side note the two commands below can be used to disable LMHOSTS and NetBIOS
$CIMInstance = Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration
$CIMInstance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}
Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }


.INPUTS
None


.OUTPUTS
None


.LINK
https://osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
#>
Function Disable-NetBIOSandLMHOSTS {
    [CmdletBinding(DefaultParameterSetName='Local')]
        param(
            [Parameter(
                ParameterSetName='Remote',
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define a remote computer(s) you wish to disable NetBIOS on. `n[E] EXAMPLE: Desktop01.domain.com, DC01, DHCP.domain.com")]  # End Parameter
            [String[]]$ComputerName,

            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$UseSSL,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$Undo,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$UseDHCPNetBIOSSetting,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$EnableLMHOSTS
        )  # End param

    If ((Get-CimInstance -ClassName Win32_ComputerSystem).PartofDomain) {

        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

    }  # End If

    Switch ($PSCmdlet.ParameterSetName) {

        'Remote' {

            $Bool = $False
            If ($UseSSL.IsPresent) {

                $Bool = $True

            }  # End If

            $Lmhost = $False
            If ($EnableLMHOSTS.IsPresent) {

                $Lmhost = $True

            }  # End If

            ForEach ($C in $ComputerName) {

                Write-Verbose "Changing NetBIOS settings on $C"
                If ($C -notlike "*.$Domain") {

                    $C = "$C.$Domain"

                }  # End If

                Invoke-Command -ArgumentList $Undo,$UseDHCPNetBIOSSetting,$Lmhost -HideComputerName $C -UseSSL:$Bool -ScriptBlock {

                    $Undo = $Args[0]
                    $UseDHCPNetBIOSSetting = $Args[1]
                    $Lmhost = $Args[2]
                    $Value = 2

                    If ($Lmhost -eq $True) {

                        Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }

                    }  # End If
                    ElseIf ($Lmhost -eq $False) {

                        Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $True; WINSEnableLMHostsLookup = $True }

                    }  # End ElseIf


                    If ($Undo.IsPresent) {

                        Write-Verbose "NetBIOS will be ENABLED"
                        $Value = 1

                    }  # End If
                    ElseIf ($UseDHCPNetBIOSSetting.IsPresent) {

                        Write-Verbose "NetBIOS Setting will be determined by the DHCP server reservation"
                        $Value = 0

                    }  # End ElseIf

                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions -Value $Value
                    $CurrentSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions | Select-Object -Property NetbiosOptions -Unique

                    If ($CurrentSetting.NetbiosOptions -eq 2) {

                        Write-Output "[*] NetBIOS has been Disabled on $env:COMPUTERNAME"

                    }  # End If
                    Else {

                        Write-Output "[!] Not all interfaces have NetBIOS disabled on $env:COMPUTERNAME"
                        $CurrentSetting

                    }  # End Else

                    $LMSetting = (Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration).WINSEnableLMHostsLookup | Select-Object -Unique
                    If ($LMSetting -eq $False) {

                        Write-Output "[*] The use of the LMHOSTS file has been disabled on $env:COMPUTERNAME"

                    }  # End If
                    Else {

                        Write-Output "[!] The use of the LMHOSTS file has been enabled on $env:COMPUTERNAME"

                    }  # End Else

                }  # End Invoke-Command

            }  # End ForEach

        }  # End Switch Remote

        'Local' {

            If ($EnableLMHOSTS.IsPresent) {

                Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $True; WINSEnableLMHostsLookup = $True }

            }  # End If
            Else {

                Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }

            }  # End ElseIf

            $Value = 2
            If ($Undo.IsPresent) {

                Write-Verbose "NetBIOS will be ENABLED"
                $Value = 1

            }  # End If
            ElseIf ($UseDHCPNetBIOSSetting.IsPresent) {

                Write-Verbose "NetBIOS Setting will be determined by the DHCP server reservation"
                $Value = 0

            }  # End ElseIf


            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions -Value $Value
            $CurrentSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions | Select-Object -Property NetbiosOptions -Unique
            If ($CurrentSetting.NetbiosOptions -eq 2) {

                Write-Output "[*] NetBIOS has been Disabled on $env:COMPUTERNAME"

            }  # End If
            Else {

                Write-Output "[!] Not all interfaces have NetBIOS disabled on $env:COMPUTERNAME"
                $CurrentSetting

            }  # End Else

            $LMSetting = (Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration).WINSEnableLMHostsLookup | Select-Object -Unique
            If ($LMSetting -eq $False) {

                Write-Output "[*] The use of the LMHOSTS file has been disabled on $env:COMPUTERNAME"

            }  # End If
            Else {

                Write-Output "[!] The use of the LMHOSTS file has been enabled on $env:COMPUTERNAME"

            }  # End Else

        }  # End Switch Local

    }  # End Switch

}  # End Function Disable-NetBIOSandLMHOSTS

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbiIdWygOprUiUJvU7+IsMzOr
# rlugggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FLYD2ToPv9tXQdtsjtvv4KkVLL3BMA0GCSqGSIb3DQEBAQUABIIBAEvrvYJUWXyN
# U8kncf/88jTR/z8UesrO5zuAiJoOZvoioTB51In/ThtU+Uh7Xx7ON0hosa/DuDyu
# fhcvhcqtYJbdosFHBMsyLSWnz7V8BXnQYOtuzmrcJDCw7vfZAm9NUu08BVVA4wVw
# +9mZYjcZmadGLTMmlYDtZlYD6nAjRKKKa7IdVhCHb+qlR19dCa5VS/Z4v5tUjOgH
# +Ugl5Hby/8aPX6jp+fOkz/xTGNmpWYX9U0W4GmuIO05wc5InEcmLckmo+Dqqexxg
# 0hMSGnWqJPWBwshdSUItGPFPiUnO8PaRI888NytWjnJ1wlJFGfA/H2YG7fNN+eYH
# BimDzfy+SnE=
# SIG # End signature block
