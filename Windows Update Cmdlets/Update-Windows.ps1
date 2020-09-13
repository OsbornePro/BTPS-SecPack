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
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
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

	If ($Error)
	{

		$Error.Clear()

	} # End If

	Write-Verbose "`n`tInitialising and Checking for Applicable Updates. Please wait ..."

	$Result = $UpdateSearch.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

	If ($Result.Updates.Count -EQ 0)
	{

		Write-Verbose "`t$env:COMPUTERNAME is currently up to date."

	} # End if
	Else
	{

		$ReportFile = "C:\Windows\Temp\$env:COMPUTERNAME\$env:COMPUTERNAME`_Report_$FormattedDate.txt"

		If (Test-Path -Path $ReportFile)
		{

			Write-Verbose "Update attempt was run already today. Previous attempt saved as a .txt.old file. New File is located at the following location. `nLOCATION:$ReportFile"
			Rename-Item -Path $ReportFile -NewName ("$ReportFile.old") -Force

		} # End If
		Elseif (!(Test-Path -Path "C:\Windows\Temp\$env:COMPUTERNAME"))
		{

			Write-Verbose "Logging folder previously did not exist and is being created at the below location. `nLOCATION: C:\Windows\Temp\$env:COMPUTERNAME"
			New-Item -Path "C:\Windows\Temp\$env:COMPUTERNAME" -ItemType Directory -Force | Out-Null

		} # End Elseif

		New-Item -Path $ReportFile -Type 'File' -Force -Value "#===================================================================#`n#                            Update Report                           #`n#===================================================================#" | Out-Null

		Add-Content -Path $ReportFile -Value "`n`nComputer Hostname : $env:COMPUTERNAME`r`nCreation Date     : $Today`rReport Directory  : C:\Windows\Temp\$env:COMPUTERNAME`r`n"
		Add-Content -Path $ReportFile -Value "---------------------------------------------------------------------`nAVAILABLE UPDATES`n---------------------------------------------------------------------`r"

		Write-Verbose "`t Preparing List of Applicable Updates For $env:COMPUTERNAME..." 

		For ($Counter = 0; $Counter -lt $Result.Updates.Count; $Counter++)
		{

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

		For ($Counter = 0; $Counter -LT $Result.Updates.Count; $Counter++)
		{

			$UpdateCollection.Add($UpdatesList.Item($Counter)) | Out-Null
			$ShowThis = $UpdatesList.Item($Counter).Title
			$DisplayCount = $Counter + 1

			Add-Content -Path $ReportFile -Value "$DisplayCount.) Downloading Update: $ShowThis `r"

			$Downloader.Updates = $UpdateCollection
			$Track = $Downloader.Download()

			If (($Track.HResult -EQ 0) -AND ($Track.ResultCode -EQ 2))
			{

				Add-Content -Path $ReportFile -Value "`tDownload Status: SUCCESS"

				If ($ShowThis -like ((Get-Variable -Name UpdateResultInfo($Counter)).Title))
				{

					Add-Member -InputObject (Get-Variable -Name UpdateResultInfo($Counter)) -NotePropertyName "DownloadStatus" -NotePropertyValue 'Successfully Downloaded'

				} # End If

			} # End If

			Else
			{

				$FailError = $Error[0]

				Add-Content -Path $ReportFile -Value "`tDownload Status: FAILED With Error `n`t`t $FailError"

				If ($ShowThis -like ((Get-Variable -Name UpdateResultInfo($Counter)).Title))
				{

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

		For ($Counter = 0; $Counter -lt $UpdateCollection.Count; $Counter++)
		{

			$Track = $Null
			$DisplayCount = $Counter + 1
			$WriteThis = $UpdateCollection.Item($Counter).Title

			Add-Content -Path $ReportFile -Value "$DisplayCount.) Installing Update: $WriteThis `r"

			$Installer.Updates = $UpdateCollection

			Try
			{

				$Track = $Installer.Install()

				Add-Content -Path $ReportFile -Value "    - Update Installation Status: SUCCESS`n"

				If ($WriteThis -like ((Get-Variable -Name UpdateResultInfo($Counter)).Title))
				{

					Add-Member -InputObject (Get-Variable -Name UpdateResultInfo($Counter)) -NotePropertyName "InstallStatus" -NotePropertyValue 'Successfully Installed'

				} # End If

			} # End Try
			Catch
			{

				[System.Exception]

				$InstallError = $Error[0]

				Add-Content -Path $ReportFile -Value "    - Update Installation Status: FAILED With Error `n`t`t$InstallError`r"

				If ($WriteThis -like ((Get-Variable -Name UpdateResultInfo($Counter)).Title))
				{

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