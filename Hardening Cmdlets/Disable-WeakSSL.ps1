<#
.SYNOPSIS
This cmdlet was created to disable weak SSL protocols and Ciphers on a Windows Client and Server. If no parameters are specified, TLSv1.2, TLSv1.3 and AES256 are enabled and NULL encryption is disabled. Other ciphers can be disabled my individually specifying their values or by using the -CISBenchmarkRecommendations parameter.


.DESCRIPTION
This cmdlet has the option to disable the weak ciphers such as TipleDES, RC4, and disabled null. SSL 2.0, 3.0, TLS 1.0 are disabled in another option. TLSv1.2, TLSv1.3 and AES 256 get enabled and NULL encryption is always disabled with this cmdlet.


.PARAMETER CISBenchmarkRecommendations
Indicates you want to apply the CIS Benchmark recommendations to disable all weak protocols and enable all strong protocols on client and server

.PARAMETER WeakTLSCipherSuites
Indicates you want to disable all Weak TLS Cipher Suites

.PARAMETER TripleDES
Indicates you want to disable the weak DES ciphers

.PARAMETER RC4
Indicates you want to disable the weak RC4 ciphers

.PARAMETER AES128
Indicates you want to disable the weak AES128 ciphers

.PARAMETER SSLv2
Indicates you want to disable SSLv2

.PARAMETER SSLv3
Indicates you want to disable SSLv3

.PARAMETER TLSv1
Indicates you want to disable TLSv1

.PARAMETER TLSv11
Indicates you want to disable TLSv11

.PARAMETER DisableTLSv13
Indicates you want to disable TLSv1.3

.PARAMETER EnableTLSv13
Indicates you want to enable TLSv1.3. If TLS 1.3 is enabled and the certificate or server is not configured for it's use you will be unable to reach the HTTPS or other SSL encrypted service. Use the -DisableTLS13 switch to disable TLS1.3


.EXAMPLE
Disable-WeakSSL -WeakTLSCipherSuites -TripleDES -RC4 -SSLv2 -SSLv3 -TLSv1 -TLSv11
# This enables TLSv1.2, TLSv1.3 and disables Null encryption, TripleDES, RC4, SSLv2, SSLv3, TLSv1, and TLSv1.1. This leaves AES 128 available for use as well as AES 256


.EXAMPLE
Disable-WeakSSL -CISBenchmarkRecommendations
# This example enables all of the strong protocols and disables all the weak ones in accordance with the CIS Benchmarks.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


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
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Disable-WeakSSL {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$CISBenchmarkRecommendations,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$WeakTLSCipherSuites,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$TripleDES,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$RC4,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$AES128,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$SSLv2,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$SSLv3,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$TLSv1,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$TLSv11,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$DisableTLSv13,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$EnableTLSv13
        ) # End param


    If (($WeakTLSCipherSuites.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {

        Write-Verbose "Disabling Weak TLS Ciphers"

        Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_MD5" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_GCM_SHA384" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_GCM_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_CBC_SHA384" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA384" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA256" -ErrorAction SilentlyContinue | Out-Null

        Write-Output "=============================================================================================="
        Write-Output "|        A LIST OF ALLOWED TLS CIPHER SUITES ARE BELOW                                       |"
        Write-Output "=============================================================================================="
        Get-TlsCipherSuite | Format-Table -Property Name,Certificate,Exchange,Hash

    }  # End If WeakCiphers


    Write-Verbose "Disabling NULL Ciphers"

    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    If (($TripleDES.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent)) {

        Write-Verbose "Disabling DES Ciphers"

        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('DES 56/56')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('Triple DES 168/168')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    }  # End If


    If (($RC4.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent)) {

        Write-Verbose "Disabling RC4 ciphers"

        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 40/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 56/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 64/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 128/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    }  # End If

    If (($AES128.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent)) {

        Write-Verbose "Disabling AES 128/128"

        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 128/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    }  # End If


    Write-Verbose "Enabling AES 256/256"
    (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 256/256')
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    If (($SSLv2.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent)) {

        Write-Verbose "Disabling SSL 2.0"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null

    }  # End If

    If (($SSLv3.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent)) {
        Write-Verbose "Disabling SSL 3.0"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    }  # End If

    If (($TLSv1.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent)) {

        Write-Verbose "Disabling TLS v1.0"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    } # End If

    If (($TLSv11.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent)) {

        Write-Verbose "Disabling TLS v1.1"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    }  # End If


    Write-Verbose "Enabling TLS 1.2"

    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null


    If ($EnableTlsv13.IsPresent) {

        Write-Verbose "Enabling TLS 1.3"
        $Q = Read-Host -Prompt "If you enable TLSv1.3 on a server and the certificate or server is not configured for using that protocol, you will be unable to reach the TLS protected resource. `nAre you sure you want to continue [y/N]"

        If ($Q -like "y*")
        {

            New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null
            New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

        }  # End If

    }  # End If


    If ($DisableTlsv13.IsPresent) {

        Write-Verbose "Disabling TLS 1.3"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    }  # End If

} # End Function Disable-WeakSSL

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULEXxVhsiNP+8+pY0axlPstOk
# 8tagggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FF4mQ4WV4AJtOva3dwszLnddFBCAMA0GCSqGSIb3DQEBAQUABIIBALU9lkzGOLcW
# 88rowzVEbpERmG1CL5meihRDgY/owLbL3jC6OaMd8nV35FOP81eU8c1/OCLxYPoS
# emefUpVhF817mHkRduS3Ollm4eWLVwc9bHV5vy83nyHf70X/2dTLb+av7Cqv9tE2
# V5AkoJ/B48nAUXXnbwEOqdTiNiVYJpOJ9MC0sqLIaW2bJeF0yWyxgxhzk/1ZyB2k
# J+MD3yOqkfGRI39vsoeJ9cEfPBgSe/5krhzS1HOWG5/I0nAYhhfN3EwYIaff6y1U
# HDRbxTlC5qdTwB9ufmOKbTdO3U3Fp7O7R5XQBfNPjEV/RktDBIQ0sXdNo/I/Geqq
# uvarioTto+o=
# SIG # End signature block
