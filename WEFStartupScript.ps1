# This should script should be signed with a code signing certificate
# Have this run at startup on all devices that will be forwarding events to ensure communication with source collector

Write-Verbose "Giving NETWORK SERVICE permissions to the Security log for WEF"
cmd /c 'wevtutil sl Security /ca:O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;BO)(A;;0x1;;;SO)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;S-1-5-20)'

Write-Verbose "Add NETWORK SERVICE to event log readers group for WEF"
Add-LocalGroupMember -Group "Event Log Readers" -Member "NETWORK SERVICE" -ErrorAction SilentlyContinue | Out-Null

Write-Verbose "Ensuring WinRM service is available for WEF communication"
$EventInfo = Get-WinEvent -LogName 'Microsoft-Windows-Forwarding/Operational' -MaxEvents 1
If ($EventInfo.LevelDisplayName -ne "Information")
{

    cmd /c 'sc config WinRM type= own'

}  # End If
