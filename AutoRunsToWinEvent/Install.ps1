#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
	param ()  # End param

$AutoRunsDir = "$env:ProgramFiles\AutorunsToWinEventLog"
$TaskName = "AutorunsToWinEventLog"

New-Item -Path $AutoRunsDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

$OSArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture
$AutorunsExecutable = "Autorunsc64.exe"

If ($OSArchitecture -notmatch "64") {
    $AutorunsExecutable = "Autorunsc.exe"
}  # End If

$AutorunsPath = Join-Path -Path $AutoRunsDir -ChildPath $AutorunsExecutable
If (!(Test-Path -Path $AutorunsPath)) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "https://live.sysinternals.com/$AutorunsExecutable" -OutFile $AutorunsPath -Method GET -UserAgent ([Microsoft.PowerShell.Commands.PSUserAgent]::FireFox)
}  # End If

Remove-Item -Path "$AutoRunsDir\AutorunsToWinEventLog.ps1" -Force -ErrorAction SilentlyContinue
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/OsbornePro/BTPS-SecPack/master/AutoRunsToWinEvent/AutorunsToWinEventLog.ps1" -Method GET -UserAgent ([Microsoft.PowerShell.Commands.PSUserAgent]::FireFox) -OutFile "$AutoRunsDir\AutorunsToWinEventLog.ps1"

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoLogo -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$AutoRunsDir\AutorunsToWinEventLog.ps1`""
$Trigger = New-ScheduledTaskTrigger -Daily -At 10am
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount
Try {
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -ErrorAction Stop
} Catch [Microsoft.Management.Infrastructure.CimException] {
    Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Scheduled task already exists"
} Catch {
    Throw $_
}  # End Try Catch Catch

$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 1 -StartWhenAvailable
Set-ScheduledTask -TaskName $TaskName -Settings $Settings
