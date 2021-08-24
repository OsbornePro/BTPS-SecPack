<#
.SYNOPSIS
This cmdlet was created to update Windows when updates are available. This cmdlet also creates logs of update attempts System Administrators will be alerted if updates fail. Originally I had this function upload the csv contents into a SQL database. To better conform to PowerShell scripting guidelines I changed this behavior.

.DESCRIPTION
This cmdlet updates windows, logs results, and alerts administrators of failures.


.EXAMPLE
Update-Windows
# This example installs all missing Windows Updates


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


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

.INPUTS
None

.OUTPUTS
None

#>
Function Update-Windows {
	[CmdletBinding()]
		param () # End param

	$ErrorActionPreference = "SilentlyContinue"
	$Today = Get-Date
	$FormattedDate = Get-Date -Format MM.dd.yyyy
	$UpdateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
	$UpdateSearch = New-Object -ComObject Microsoft.Update.Searcher
	$Session = New-Object -ComObject Microsoft.Update.Session

	If ($Error)	{

		$Error.Clear()

	} # End If

	Write-Verbose "`n`tInitialising and Checking for Applicable Updates. Please wait ..."
	$Result = $UpdateSearch.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
	If ($Result.Updates.Count -EQ 0) {

		Write-Verbose "`t$env:COMPUTERNAME is currently up to date."

	} # End If
	Else {

		$ReportFile = "C:\Windows\Temp\$env:COMPUTERNAME\$env:COMPUTERNAME`_Report_$FormattedDate.txt"
		If (Test-Path -Path $ReportFile) {

			Write-Verbose "Update attempt was run already today. Previous attempt saved as a .txt.old file. New File is located at the following location. `nLOCATION:$ReportFile"
			Rename-Item -Path $ReportFile -NewName ("$ReportFile.old") -Force

		} # End If
		Elseif (!(Test-Path -Path "C:\Windows\Temp\$env:COMPUTERNAME")) {

			Write-Verbose "Logging folder previously did not exist and is being created at the below location. `nLOCATION: C:\Windows\Temp\$env:COMPUTERNAME"
			New-Item -Path "C:\Windows\Temp\$env:COMPUTERNAME" -ItemType Directory -Force | Out-Null

		} # End Elseif

		New-Item -Path $ReportFile -Type 'File' -Force -Value "#===================================================================#`n#                            Update Report                           #`n#===================================================================#" | Out-Null

		Add-Content -Path $ReportFile -Value "`n`nComputer Hostname : $env:COMPUTERNAME`r`nCreation Date     : $Today`rReport Directory  : C:\Windows\Temp\$env:COMPUTERNAME`r`n"
		Add-Content -Path $ReportFile -Value "---------------------------------------------------------------------`nAVAILABLE UPDATES`n---------------------------------------------------------------------`r"

		Write-Verbose "`t Preparing List of Applicable Updates For $env:COMPUTERNAME..." 

		For ($Counter = 0; $Counter -lt $Result.Updates.Count; $Counter++) {

			$DisplayCount = $Counter + 1
			$Update = $Result.Updates.Item($Counter)
			$UpdateTitle = $Update.Title

			Add-Content -Path $ReportFile -Value "$DisplayCount.) $UpdateTitle"

			$UpdateResultInfo = New-Object -TypeName System.Management.Automation.PSCustomObject -Property @{
				UpdateTitle = $UpdateTitle
				Hostname    = $env:COMPUTERNAME
				Date	    = $FormattedDate } # End Property

			New-Variable -Name UpdateResultInfo$Counter -Value $UpdateResultInfo

		} # End For

		$Counter = 0
		$DisplayCount = 0

		Write-Verbose "`t Initialising Download of Applicable Updates ..."

		Add-Content -Path $ReportFile -Value "`n---------------------------------------------------------------------`nINITIALISING UPDATE DOWNLOADS`n---------------------------------------------------------------------`n"

		$Downloader = $Session.CreateUpdateDownloader()
		$UpdatesList = $Result.Updates

		For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++) {

			$UpdateCollection.Add($UpdatesList.Item($Counter)) | Out-Null
			$ShowThis = $UpdatesList.Item($Counter).Title
			$DisplayCount = $Counter + 1

			Add-Content -Path $ReportFile -Value "$DisplayCount.) Downloading Update: $ShowThis `r"

			$Downloader.Updates = $UpdateCollection
			$Track = $Downloader.Download()

			If (($Track.HResult -EQ 0) -AND ($Track.ResultCode -EQ 2)) {

				Add-Content -Path $ReportFile -Value "`tDownload Status: SUCCESS"
				If ($ShowThis -like ((Get-Variable -Name UpdateResultInfo($Counter)).Title)) {

					Add-Member -InputObject (Get-Variable -Name UpdateResultInfo($Counter)) -NotePropertyName "DownloadStatus" -NotePropertyValue 'Successfully Downloaded'

				} # End If

			} # End If
			Else {

				$FailError = $Error[0]
				Add-Content -Path $ReportFile -Value "`tDownload Status: FAILED With Error `n`t`t $FailError"
				If ($ShowThis -like ((Get-Variable -Name UpdateResultInfo($Counter)).Title))  {

					Add-Member -InputObject (Get-Variable -Name UpdateResultInfo($Counter)) -NotePropertyName "DownloadStatus" -NotePropertyValue $FailError

				} # End If

				$Error.Clear()
				Add-content -Path $ReportFile -Value "`r"

			} # End Else

		} # End For

		$Counter = 0
		$DisplayCount = 0

		Write-Verbose "`tStarting Installation of Downloaded Updates ..."
		Add-Content -Path $ReportFile -Value "---------------------------------------------------------------------`nUPDATE INSTALLATION`n---------------------------------------------------------------------`n"

		$Installer = New-Object -ComObject Microsoft.Update.Installer

		For ($Counter = 0; $Counter -lt $UpdateCollection.Count; $Counter++) {

			$Track = $Null
			$DisplayCount = $Counter + 1
			$WriteThis = $UpdateCollection.Item($Counter).Title

			Add-Content -Path $ReportFile -Value "$DisplayCount.) Installing Update: $WriteThis `r"

			$Installer.Updates = $UpdateCollection

			Try {

				$Track = $Installer.Install()
				Add-Content -Path $ReportFile -Value "    - Update Installation Status: SUCCESS`n"

				If ($WriteThis -like ((Get-Variable -Name UpdateResultInfo($Counter)).Title)) {

					Add-Member -InputObject (Get-Variable -Name UpdateResultInfo($Counter)) -NotePropertyName "InstallStatus" -NotePropertyValue 'Successfully Installed'

				} # End If

			} # End Try
			Catch {

				[System.Exception]
				$InstallError = $Error[0]

				Add-Content -Path $ReportFile -Value "    - Update Installation Status: FAILED With Error `n`t`t$InstallError`r"
				If ($WriteThis -like ((Get-Variable -Name UpdateResultInfo($Counter)).Title)) {

					Add-Member -InputObject (Get-Variable -Name UpdateResultInfo($Counter)) -NotePropertyName "InstallStatus" -NotePropertyValue $InstallError

				} # End If

				$Error.Clear()

			} # End Catch

		} # End For

		Add-Content -Path $ReportFile -Value "#===================================================================#`n#                         END OF REPORT                             #`n#===================================================================#"

		$Obj = New-Object -TypeName PSCustomObject -Properties @{
					UpdateTitle=$UpdateResultInfo.UpdateTitle
					HostName=$UpdateResultInfo.HostName
					Date=$UpdateResultInfo.Date
					DownloadStatus=$UpdateResultInfo.DownloadStatus
					InstallStatus=$UpdateResultInfo.InstallStatus
		} # End Properties

		Write-Output $Obj 

    } # End Else

} # End Funtion Update-Windows

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUweT1gpPXdRnGffD95oBb+bE/
# adigggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FO7RT7bJ1633rOfp/T+QCnUo5oPrMA0GCSqGSIb3DQEBAQUABIIBACY1BneWYa+q
# w/0BaxnmD+/yVDUGQe/NJwBHsTsc8re70/4hnk1s4iUEVKsyoiEXYNjuuGDkzP3q
# Xi2Ywlf5eBoqV6TCOwRVt7BergMPOsbT81JcCHi4niN05Ydjjj2uGAHAjy1X9F79
# z67gbI2Qx+PHNXXO8xMDeKeBXs68Jzc/8zAVgL08wVnJhgFZzMY4FtzAXvI6j46g
# W6R/vssDPRkaAC7MJe2KIc0DEcCtOxYtfnfw2TskmDo5P0ULhM4p7E/mv8kw3RCD
# /Bva7V+WrvNX+UhliIRx7VcKtsJlxf8pJOY8pqxuMZ0CM+WeZ+ciF2jAJts6nVql
# 8scdd3GFcQs=
# SIG # End signature block
