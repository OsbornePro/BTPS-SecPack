#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
  param ()

Unregister-ScheduledTask -TaskName "AutorunsToWinEventLog" -Confirm:$False -ErrorAction SilentlyContinue
Remove-EventLog -LogName "Autoruns" -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramFiles\AutorunsToWinEventLog" -Recurse -Force -ErrorAction SilentlyContinue
