<#
.SYNOPSIS
This cmdlet is used to easily enable the Hypertext Strict Transport Security (HSTS) Header for an IIS hosted site. It also is able to set other attributes in that same property area such as includeSubDomains and redirectHTTPtoHTTPS. I have not included the Preload attribute because this can cause access issues to a site and it should not be so easily enabled without having more informaton on what it does.


.DESCRIPTION
Enabling Hypertext Strict Transport Security (HSTS) is done to prevent SSL striping and encryption downgrade attacks.


.PARAMETER ComputerName
Define remote computer(s) you wish to enable HSTS on

.PARAMETER UseSSL
Indicates you wish to use WinRM over HTTPS for remote connections instead of plain WinRM

.PARAMETER SiteName
Define the site(s) on the remote device to apply your HSTS values too. If this is not defined the changes will be applied to every IIS hosted site

.PARAMETER MaxAge
Defines the max age value for a certifiate in seconds. The default value I have set is 2 years. The minimum value allowed is 1 year or 31536000 seconds

.PARAMETER IncludeSubDomains
This switch parameter indicates that you want to apply HSTS to all subdomains as well

.PARAMETER ForceHTTPS
Indicates that you want all HTTP traffic to a site redirected to HTTPS

.PARAMETER EnableOCSPStapling
Indicates the OCSP Stapling should be performed


.EXAMPLE
Enable-HSTS -MaxAge 63072000 -IncludeSubDomains -ForceHTTPS
# This example enables HSTS, sets a max-age value of 2 years and enables the IncludeSubdomains and RedirectHTTPtoHTTPS attributes

.EXAMPLE
Enable-HSTS -MaxAge (New-TimeSpan -Days 365).TotalSeconds -ForceHTTPS
# This example enables HSTS, sets a max-age value of 1 year and enables the RedirectHTTPtoHTTPS attribute

.EXAMPLE
Enable-HSTS
# This example enables HSTS on all IIS server sites and sets the max-age attribute to 2 years

.EXAMPLE
Enable-HSTS -ComputerName Site.domain.com,WebServer.domain.com -ForceHTTPS
# This example enables HSTS and sets the Force HTTPS attribute on remote machines Site.domain.com and WebServer.domain.com using WinRM and sets the Max Age attribute to 2 years

.EXAMPLE
Enable-HSTS -ComputerName Site.domain.com,WebServer.domain.com -UseSSL -ForceHTTPS -EnableOCSPStapling
# This example enables OCSP Stapling and HSTS and sets the Force HTTPS attribute on remote machines Site.domain.com and WebServer.domain.com using WinRM over HTTPS and sets the Max Age attribute to 2 years


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
System.Array


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://btpssecpack.osbornepro.com
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Enable-HSTS {
    [CmdletBinding(
        DefaultParameterSetName='Local',
        SupportsShouldProcess, ConfirmImpact = "Medium")]  # End CmdletBinding
    [OutputType([System.Array])]
        param(
            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Enter a computer FQDN or hostname you wish to enable HSTS on. Separte multiple values with a comma. WinRM must be enabled for this too work. `n[E] EXAMPLE: 'DC01.domain.com','DHCP.domain.com'")]  # End Parameter
            [String[]]$ComputerName,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String[]]$Site,

            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$UseSSL,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateScript({$_ -ge 31536000 -or $_ -eq 0})]
            [Int64]$MaxAge = 63072000,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$IncludeSubDomains,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$ForceHTTPS,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$EnableOCSPStapling
        )  # End param


    If ($PSCmdlet.ParameterSetName -eq 'Remote') {

        $Bool = $False
        If ($UseSSL.IsPresent) {

            $Bool = $True

        }  # End If


        ForEach ($C in $ComputerName) {

            Write-Warning "This does not work yet. I am still trying to trouble shoot the issue here"
            If ($UseSSL.IsPresent -and $C -notlike "*.$env:USERDNSDOMAIN") {

                $C = $C + ".$env:USERDNSDOMAIN"

            }  # End If

            $EnableOCSP = $False
            If ($EnableOCSPStapling.IsPresent) {

                $EnableOCSP = $True

            }  # End If

            $Session = New-PSSession -ComputerName $C -Name $C -EnableNetworkAccess -UseSSL:$Bool
            Invoke-Command -ArgumentList $MaxAge,$IncludeSubDomains,$ForceHTTPS,$Site,$EnableOCSP -Session $Session -ScriptBlock {

                $MaxAge = $Args[0]
                $IncludeSubDomains = $Args[1]
                $ForceHTTPS = $Args[2]
                If ($Args[3]) { $Site = $Args[3] }
                $EnableOCSP = $Args[4]

                If ($EnableOCSP) {

                    Write-Output "[*] Enabling OCSP Stapling"
                    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\" -Name "EnableOcspStaplingForSni" -PropertyType DWord -Value 1

                }  # End If

                $Count = 0
                $Obj = @()
                $SiteElements = @()
                $HstsElements = @()

                Import-Module -Name IISAdministration -ErrorAction Stop
                Start-IISCommitDelay

                Write-Verbose "Getting Site Collection Information"
                $SiteCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection

                If (!($Site)) {

                    Write-Verbose "Obtaining all available Site Names"
                    $SiteNames = ($SiteCollection | Select-Object -ExpandProperty RawAttributes).name

                }  # End If
                Else {

                    $SiteNames = $Site

                }  # End If

                Write-Verbose "Obtaining site elements"
                ForEach ($SiteName in $SiteNames) {

                    New-Variable -Name ("$Site" + $Count.ToString()) -Value $SiteName
                    $Count++

                    Write-Verbose "Building element from $SiteName"
                    $SiteElements += Get-IISConfigCollectionElement -ConfigCollection $SiteCollection -ConfigAttribute @{"name"="$SiteName"}

                }  # End ForEach


                Write-Verbose "Evaluating current HSTS Setting"
                ForEach ($SiteElement in $SiteElements) {

                    $HstsElements += Get-IISConfigElement -ConfigElement $SiteElement -ChildElementName "hsts"

                }  # End

                $Count = 0
                If ($PSCmdlet.ShouldProcess($MaxAge, 'Modify HSTS settings and attributes for IIS sites')) {

                    Write-Output "[*] Enabling HSTS on available sites"
                    ForEach ($HstsElement in $HstsElements) {

                        If ($HstsElement.RawAttributes.enabled -eq 'False') {

                            Write-Verbose "Enabling HTSTS attribute"
                            Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "Enabled" -AttributeValue $True

                        }  # End If
                        Else {

                            Write-Output "[*] HSTS is already enabled"

                        }  # End Else


                        If ($HstsElement.RawAttributes.'max-age' -ne $MaxAge) {

                            Write-Verbose "Setting the max-age attribute. For more [max-age] information, refer to https://hstspreload.org/"
                            Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "max-age" -AttributeValue $MaxAge

                        }  # End If
                        Else {

                            Write-Output "[*] Max-Age is already set to $MaxAge"

                        }  # End Else


                        If (($IncludeSubDomains.IsPresent) -and ($HstsElements.RawAttributes.includeSubDomains -eq 'False')) {

                            Write-Verbose "Apply to all subdomains"
                            Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "includeSubDomains" -AttributeValue 'True'

                        }  # End If
                        ElseIf ($HstsElements.RawAttributes.includeSubDomains -eq 'True') {

                            Write-Output "[*] IncludeSubDomains property is already enabled"

                        }  # End ElseIf

                        If (($ForceHTTPS.IsPresent) -and ($HstsElements.RawAttributes.redirectHttpToHttps -eq 'False')) {

                            Write-Verbose "Redirecting HTTP traffic to HTTPS"
                            Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "redirectHttpToHttps" -AttributeValue 'True'


                        }  # End If
                        ElseIf ($HstsElements.RawAttributes.redirectHttpToHttps -eq 'True') {

                            Write-Output "[*] Redirect to HTTPS attribute is already enabled"

                        }  # End ElseIf

                        $Obj += New-Object -TypeName PSObject -Property @{Site=(Get-Variable -ErrorAction SilentlyContinue -ValueOnly -Name ($Site + $Count.ToString())); HSTS=$HstsElement.RawAttributes.enabled; MaxAge=$HstsElement.RawAttributes.'max-age'; IncludeSubDomains=$HstsElements.RawAttributes.includeSubDomains; RedirectHTTPtoHTTPS=$HstsElements.RawAttributes.redirectHttpToHttps}

                        $Count++

                    }  # End ForEach

                    If ($Obj.Site) {

                        $Obj

                    }  # End If
                    Else {

                        Write-Output "[*] No changes needed to be carried out"

                    }  # End Else

                }  # End If ShouldProcess

                Stop-IISCommitDelay -ErrorAction SilentlyContinue | Out-NUll

            }  # End ScriptBlock

        }  # End ForEach

    }  # End If
    Else {

        $Count = 0
        $Obj = @()
        $SiteElements = @()
        $HstsElements = @()

        If ($EnableOCSPStapling) {

            Write-Output "[*] Enabling OCSP Stapling"
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\" -Name "EnableOcspStaplingForSni" -PropertyType DWord -Value 1

        }  # End If

        Import-Module -Name IISAdministration -ErrorAction Stop
        Start-IISCommitDelay

        Write-Verbose "Getting Site Collection Information"
        $SiteCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection

        If (!($Site)) {

            Write-Verbose "Obtaining all available Site Names"
            $SiteNames = ($SiteCollection | Select-Object -ExpandProperty RawAttributes).name

        }  # End If
        Else {

            $SiteNames = $Site

        }  # End If

        Write-Verbose "Obtaining site elements"
        ForEach ($SiteName in $SiteNames) {

            New-Variable -Name ("$Site" + $Count.ToString()) -Value $SiteName
            $Count++

            Write-Verbose "Building element from $SiteName"
            $SiteElements += Get-IISConfigCollectionElement -ConfigCollection $SiteCollection -ConfigAttribute @{"name"="$SiteName"}

        }  # End ForEach


        Write-Verbose "Evaluating current HSTS Setting"
        ForEach ($SiteElement in $SiteElements) {

            $HstsElements += Get-IISConfigElement -ConfigElement $SiteElement -ChildElementName "hsts"

        }  # End

        $Count = 0
        If ($PSCmdlet.ShouldProcess($MaxAge, 'Modify HSTS settings and attributes for IIS sites')) {

            Write-Output "[*] Enabling HSTS on available sites"
            ForEach ($HstsElement in $HstsElements) {

                If ($HstsElement.RawAttributes.enabled -eq 'False') {

                    Write-Verbose "Enabling HTSTS attribute"
                    Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "Enabled" -AttributeValue $True

                }  # End If
                Else {

                    Write-Output "[*] HSTS is already enabled"

                }  # End Else


                If ($HstsElement.RawAttributes.'max-age' -ne $MaxAge) {

                    Write-Verbose "Setting the max-age attribute. For more [max-age] information, refer to https://hstspreload.org/"
                    Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "max-age" -AttributeValue $MaxAge

                }  # End If
                Else {

                    Write-Output "[*] Max-Age is already set to $MaxAge"

                }  # End Else


                If (($IncludeSubDomains.IsPresent) -and ($HstsElements.RawAttributes.includeSubDomains -eq 'False')) {

                    Write-Verbose "Apply to all subdomains"
                    Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "includeSubDomains" -AttributeValue 'True'

                }  # End If
                ElseIf ($HstsElements.RawAttributes.includeSubDomains -eq 'True') {

                    Write-Output "[*] IncludeSubDomains property is already enabled"

                }  # End ElseIf

                If (($ForceHTTPS.IsPresent) -and ($HstsElements.RawAttributes.redirectHttpToHttps -eq 'False')) {

                    Write-Verbose "Redirecting HTTP traffic to HTTPS"
                    Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "redirectHttpToHttps" -AttributeValue 'True'


                }  # End If
                ElseIf ($HstsElements.RawAttributes.redirectHttpToHttps -eq 'True') {

                    Write-Output "[*] Redirect to HTTPS attribute is already enabled"

                }  # End ElseIf

                $Obj += New-Object -TypeName PSObject -Property @{Site=(Get-Variable -ErrorAction SilentlyContinue -ValueOnly -Name ($Site + $Count.ToString())); HSTS=$HstsElement.RawAttributes.enabled; MaxAge=$HstsElement.RawAttributes.'max-age'; IncludeSubDomains=$HstsElements.RawAttributes.includeSubDomains; RedirectHTTPtoHTTPS=$HstsElements.RawAttributes.redirectHttpToHttps}

                $Count++

            }  # End ForEach

            If ($Obj.Site) {

                $Obj

            }  # End If
            Else {

                Write-Output "[*] No changes needed to be carried out"

            }  # End Else

        }  # End If ShouldProcess

        Stop-IISCommitDelay -ErrorAction SilentlyContinue | Out-NUll

    }  # End Else

}  # End Function Enable-HSTS

# SIG # Begin signature block
# MIIRdQYJKoZIhvcNAQcCoIIRZjCCEWICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUO4F9GwK82TKXOvQzHNDPTfAR
# z6Cggg58MIIEfTCCA2WgAwIBAgIDG+cVMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
# BAYTAlVTMSEwHwYDVQQKExhUaGUgR28gRGFkZHkgR3JvdXAsIEluYy4xMTAvBgNV
# BAsTKEdvIERhZGR5IENsYXNzIDIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcN
# MTQwMTAxMDcwMDAwWhcNMzEwNTMwMDcwMDAwWjCBgzELMAkGA1UEBhMCVVMxEDAO
# BgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdv
# RGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
# AQEAv3FiCPH6WTT3G8kYo/eASVjpIoMTpsUgQwE7hPHmhUmfJ+r2hBtOoLTbcJjH
# MgGxBT4HTu70+k8vWTAi56sZVmvigAf88xZ1gDlRe+X5NbZ0TqmNghPktj+pA4P6
# or6KFWp/3gvDthkUBcrqw6gElDtGfDIN8wBmIsiNaW02jBEYt9OyHGC0OPoCjM7T
# 3UYH3go+6118yHz7sCtTpJJiaVElBWEaRIGMLKlDliPfrDqBmg4pxRyp6V0etp6e
# MAo5zvGIgPtLXcwy7IViQyU0AlYnAZG0O3AqP26x6JyIAX2f1PnbU21gnb8s51ir
# uF9G/M7EGwM8CetJMVxpRrPgRwIDAQABo4IBFzCCARMwDwYDVR0TAQH/BAUwAwEB
# /zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDqahQcQZyi27/a9BUFuIMGU2g/e
# MB8GA1UdIwQYMBaAFNLEsNKR1EwRcbNhyz2h/t2oatTjMDQGCCsGAQUFBwEBBCgw
# JjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29kYWRkeS5jb20vMDIGA1UdHwQr
# MCkwJ6AloCOGIWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20vZ2Ryb290LmNybDBGBgNV
# HSAEPzA9MDsGBFUdIAAwMzAxBggrBgEFBQcCARYlaHR0cHM6Ly9jZXJ0cy5nb2Rh
# ZGR5LmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAWQtTvZKGEack
# e+1bMc8dH2xwxbhuvk679r6XUOEwf7ooXGKUwuN+M/f7QnaF25UcjCJYdQkMiGVn
# OQoWCcWgOJekxSOTP7QYpgEGRJHjp2kntFolfzq3Ms3dhP8qOCkzpN1nsoX+oYgg
# HFCJyNwq9kIDN0zmiN/VryTyscPfzLXs4Jlet0lUIDyUGAzHHFIYSaRt4bNYC8nY
# 7NmuHDKOKHAN4v6mF56ED71XcLNa6R+ghlO773z/aQvgSMO3kwvIClTErF0UZzds
# yqUvMQg3qm5vjLyb4lddJIGvl5echK1srDdMZvNhkREg5L4wn3qkKQmw4TRfZHcY
# QFHfjDCmrzCCBNAwggO4oAMCAQICAQcwDQYJKoZIhvcNAQELBQAwgYMxCzAJBgNV
# BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow
# GAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjExMC8GA1UEAxMoR28gRGFkZHkgUm9v
# dCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjAeFw0xMTA1MDMwNzAwMDBaFw0z
# MTA1MDMwNzAwMDBaMIG0MQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTET
# MBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWRkeS5jb20sIEluYy4x
# LTArBgNVBAsTJGh0dHA6Ly9jZXJ0cy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5LzEz
# MDEGA1UEAxMqR28gRGFkZHkgU2VjdXJlIENlcnRpZmljYXRlIEF1dGhvcml0eSAt
# IEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAueDLENSvdr3Uk2Lr
# MGS4gQhswwTZYheOL/8+Zc+PzmLmPFIc2hZFS1WreGtjg2KQzg9pbJnIGhSLTMxF
# M+qI3J6jryv+gGGdeVfEzy70PzA8XUf8mha8wzeWQVGOEUtU+Ci+0Iy+8DA4HvOw
# JvhmR2Nt3nEmR484R1PRRh2049wA6kWsvbxx2apvANvbzTA6eU9fTEf4He9bwsSd
# YDuxskOR2KQzTuqz1idPrSWKpcb01dCmrnQFZFeItURV1C0qOj74uL3pMgoClGTE
# FjpQ8Uqu53kzrwwgB3/o3wQ5wmkCbGNS+nfBG8h0h8i5kxhQVDVLaU68O9NJLh/c
# wdJS+wIDAQABo4IBGjCCARYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
# AQYwHQYDVR0OBBYEFEDCvSeOzDSDMKIz1/tss/C0LIDOMB8GA1UdIwQYMBaAFDqa
# hQcQZyi27/a9BUFuIMGU2g/eMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZ29kYWRkeS5jb20vMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6
# Ly9jcmwuZ29kYWRkeS5jb20vZ2Ryb290LWcyLmNybDBGBgNVHSAEPzA9MDsGBFUd
# IAAwMzAxBggrBgEFBQcCARYlaHR0cHM6Ly9jZXJ0cy5nb2RhZGR5LmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEACH5skxDIOLiWqZBL/6FfTwTvbD6c
# iAbJUI+mc/dXMRu+vOQv2/i601vgtOfmeWIODKLXamNzMbX1qEikOwgtol2Q17R8
# JU8RVjDEtkSdeyyd5V7m7wxhqr/kKhvuhJ64g33BQ85EpxNwDZEf9MgTrYNg2dhy
# qHMkHrWsIg7KF4liWEQbq4klAQAPzcQbYttRtNMPUSqb9Lxz/HbONqTN2dgs6q6b
# 9SqykNFNdRiKP4pBkCN9W0v+pANYm0ayw2Bgg/h9UEHOwqGQw7vvAi/SFVTuRBXZ
# Cq6nijPtsS12NibcBOuf92EfFdyHb+5GliitoSZ9CgmnLgSjjbz4vAQwATCCBSMw
# ggQLoAMCAQICCFyITaAJpkgGMA0GCSqGSIb3DQEBCwUAMIG0MQswCQYDVQQGEwJV
# UzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UE
# ChMRR29EYWRkeS5jb20sIEluYy4xLTArBgNVBAsTJGh0dHA6Ly9jZXJ0cy5nb2Rh
# ZGR5LmNvbS9yZXBvc2l0b3J5LzEzMDEGA1UEAxMqR28gRGFkZHkgU2VjdXJlIENl
# cnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTIwMTExNTIzMjAyOVoXDTIxMTEw
# NDE5MzYzNlowZTELMAkGA1UEBhMCVVMxETAPBgNVBAgTCENvbG9yYWRvMRkwFwYD
# VQQHExBDb2xvcmFkbyBTcHJpbmdzMRMwEQYDVQQKEwpPc2Jvcm5lUHJvMRMwEQYD
# VQQDEwpPc2Jvcm5lUHJvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# yVegr7n+Ow+IhSE1EjY9LnGZPgX5q0Ru11TjomPaO6iYGgDfPEgUmOOa6WbRpxFQ
# GAL4+nKDbgKi2vJO/iJu9k5DKaCwCtBWba4Oj03yYItqRVj/lK02qKy2Zxt6CIcz
# RgbeaKgRMvgbFaFHwPP2hXstxXnSrg9Qnkyq4IXnarxgfsBnnzMk//o2gvfXs6hq
# rEqF1wgXh+sCWobLTOVgHXVDspU5ExH8n7KlnzLIFm1Z91aJCKqS+qxOmArTUTpG
# anwi2ezCW+YUBJdfdamHOVZTCrlpUFhq4FbxCBP/JYCQDMFTw8CzXBZwfs8im/lC
# 7q1ht4BmilJNWeXyumEPgQIDAQABo4IBhTCCAYEwDAYDVR0TAQH/BAIwADATBgNV
# HSUEDDAKBggrBgEFBQcDAzAOBgNVHQ8BAf8EBAMCB4AwNQYDVR0fBC4wLDAqoCig
# JoYkaHR0cDovL2NybC5nb2RhZGR5LmNvbS9nZGlnMnM1LTYuY3JsMF0GA1UdIARW
# MFQwSAYLYIZIAYb9bQEHFwIwOTA3BggrBgEFBQcCARYraHR0cDovL2NlcnRpZmlj
# YXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0b3J5LzAIBgZngQwBBAEwdgYIKwYBBQUH
# AQEEajBoMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wQAYI
# KwYBBQUHMAKGNGh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5jb20vcmVwb3Np
# dG9yeS9nZGlnMi5jcnQwHwYDVR0jBBgwFoAUQMK9J47MNIMwojPX+2yz8LQsgM4w
# HQYDVR0OBBYEFJFmAe6Q5d8V/j5TCtVzu61B4268MA0GCSqGSIb3DQEBCwUAA4IB
# AQBUrDd34GhhgoupvBrmiKyWsimXhKXiCtVRycqGt93hVGPtLx2gEpx9yf41R1uA
# RVN24BUfx/+AdF22D5QdX+E2K2IdCIPYKGByt9C4ln/ql2l91mPZjld6zOkPyXz6
# X8eeblPU+MnmPINysgO2Oz5h/mUYHEKgzmeSAMCoJJ2KB9uZgmcKGe8/6CREgLLT
# y7yJla0pAjxykMWcv7XTPZYjmAeUdqPxIDg+Th9wfxs8JshRtwqq6iNi+G7UCioZ
# vgj67nuaF79rYXmlDnfiGCVvSwN4Lz/81UIZTkPyGw0bewYm0KdLlo2GjADmhCsW
# TSJLDyhCfAMQByL6/tz/Ede1MYICYzCCAl8CAQEwgcEwgbQxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQK
# ExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFk
# ZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzICCFyITaAJpkgGMAkGBSsOAwIaBQCgeDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEW
# BBQ89AqZnPegp3g2rEOvSDKBxnfFqTANBgkqhkiG9w0BAQEFAASCAQDC7XP5lYrW
# gM92ycs6C1o6xwhzSo5lIrrAGzVtT4GcDSC3viwV+zaldxHux65O5D8NDLYakBJm
# 8Xm3B0kiNVKvUVKGDDrmdgeEKa8ey9sbhJ2+/qLUrMSNqitnwqiOO6FQjQ1mV5G4
# eWI1FNeYFy0ZNXdqvSsdLNKrIO3M13CDAlPqOJqUh6tzX0etE3bih8+vNaEHECWW
# XNCE55utTs7uCZkETe+X72MPkMAUEI65W9UYM1XHOjIs+QxND22i3UFNCsg+vfLI
# 6nQNvu9mEORq0+lPc+mIoN3FK1CiZgkrShDZuk1IJrH8JV7PrwlUloyWlYd1usND
# +PXiSMGbkUV4
# SIG # End signature block
