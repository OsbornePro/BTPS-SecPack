Write-Verbose -Message "[v] Create Program Files directories for Autoruns"
$AutoRunsDir = "$env:ProgramFiles\AutorunsToWinEventLog"
$TaskName = "AutorunsToWinEventLog"
New-Item -Path $AutoRunsDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

Write-Verbose -Message "[v] Download Autorunsc64.exe if it doesn't exist"
$OSArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$False).OSArchitecture
$AutorunsExecutable = "Autorunsc64.exe"
If ($OSArchitecture -notmatch "64") {

    $AutorunsExecutable = "Autorunsc.exe"

}  # End If

$AutorunsPath = "$($AutoRunsDir)\$($AutorunsExecutable)"
If (!(Test-Path -Path $AutoRunsPath)) {

  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri "https://live.sysinternals.com/$($AutorunsExecutable)" -OutFile $AutoRunsPath -Method GET -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox

}  # End If

Remove-Item -Path "$AutorunsDir\AutorunsToWinEventLog.ps1" -Force -ErrorAction SilentlyContinue | Out-Null
Start-Sleep -Seconds 1
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/AutoRunsToWinEvent/AutorunsToWinEventLog.ps1" -Method GET -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox -OutFile "$AutorunsDir\AutorunsToWinEventLog.ps1"

$Action = New-ScheduledTaskAction -Execute powershell -Argument "-NoLogo -NonInteractive -WindowStyle Hidden $AutorunsDir\AutorunsToWinEventLog.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At 10am
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount

Try {

	Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal

} Catch [Microsoft.Management.Infrastructure.CimException] {

	Write-Verbose -Message "[v] Task already exists"

} Catch {

    $Error[0]

}  # End Try Catch Catch
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 1 -StartWhenAvailable
Set-ScheduledTask -TaskName $TaskName -Settings $Settings
