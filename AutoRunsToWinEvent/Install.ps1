Write-Verbose "Create Program Files directories for Autoruns"
$AutoRunsDir = "C:\Program Files\AutorunsToWinEventLog"
If (!(Test-Path -Path $AutoRunsDir)) 
{

  New-Item -Path $AutoRunsDir -ItemType Directory -Force

}  # End If

Write-Verbose "Download Autorunsc64.exe if it doesn't exist"
$AutorunsPath = "c:\Program Files\AutorunsToWinEventLog\Autorunsc64.exe"
If (!(Test-Path -Path $AutoRunsPath)) 
{

  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri "https://live.sysinternals.com/autorunsc64.exe" -OutFile "$AutoRunsPath"

}  # End If

# Put a copy of the AutorunsToWinEventLog script in the Autoruns directory
Copy-Item -Path "$PSScriptRoot\AutorunsToWinEventLog.ps1" -Destination "$AutoRunsDir\AutorunsToWinEventLog.ps1"

$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoLogo -NonInteractive -WindowStyle Hidden C:\PROGRA~1\AutorunsToWinEventLog\AutorunsToWinEventLog.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At 10am
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount

Register-ScheduledTask -TaskName "AutorunsToWinEventLog" -Action $Action -Trigger $Trigger -Principal $Principal


$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 1 -StartWhenAvailable
Set-ScheduledTask -TaskName "AutorunsToWinEventLog" -Settings $Settings
