#Requires -Version 3.0
<#
.SYNOPSIS
Monitors elevated process execution by specified administrator accounts.


.DESCRIPTION
This script monitors Security Event ID 4688 to identify when a monitored
administrator account executes a process using an elevated token.

The script queries recent process creation events from the Security log,
extracts important event data fields, and generates an HTML email alert
containing details about the elevated process execution.

This script is intended for environments where administrator credentials
should be tightly controlled and monitored.

Audit Process Creation logging must be enabled for this script to function properly.


.PARAMETER MonitorAdmins
Specifies one or more administrator accounts to monitor for elevated
process execution activity.

The parameter accepts an array of usernames.


.EXAMPLE
PS> .\Monitor-ElevatedProcess.ps1 -MonitorAdmins "Admin1"
# Monitors the Admin1 account for elevated process execution activity.

.EXAMPLE
PS> .\Monitor-ElevatedProcess.ps1 -MonitorAdmins "Admin1","Admin2" -Verbose
# Monitors multiple administrator accounts and displays verbose output.


.INPUTS
System.String[]

You can pipe administrator account names to this script.

.OUTPUTS
System.Management.Automation.PSCustomObject

The script outputs objects containing information about elevated process activity.

.NOTES
Author: Robert H. Osborne
Company: OsbornePro
Requires: PowerShell 3.0 or later
Event ID: 4688

Required Audit Policy:
- Audit Process Creation
- Include command line in process creation events

Recommended Security Monitoring:
- PowerShell
- cmd.exe
- regedit.exe
- mmc.exe
- psexec.exe
- wscript.exe
- cscript.exe

Limitations:
- This script detects elevated process execution, not specifically UAC prompts.
- Some applications may elevate using alternate mechanisms.
- Security log retention size may impact historical visibility.
#>
[CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$True,
            HelpMessage="[?] Define the SamAccountName for the admin accounts you wish to monitor`n[EXAMPLE] Administrator`n[INPUT]"
        )]  # End Parameter
        [ValidateNotNullOrEmpty()]
        [String[]]$MonitorAdmins
    )  # End param

Function Get-EventDataValue {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory = $True
            )]  # End Parameter
            [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
    
            [Parameter(
                Mandatory = $True
            )]  # End Parameter
            [String]$Name
        )  # End param

    $EventXml = [Xml]$Event.ToXml()
    $Value = $EventXml.Event.EventData.Data | Where-Object -FilterScript { $_.Name -eq $Name } | Select-Object -ExpandProperty "#text" -First 1
    Write-Output -InputObject $Value

}  # End Function Get-EventDataValue

Try {

    Write-Verbose -Message "Searching Security log for elevated process events"
    $Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4688 and TimeCreated[timediff(@SystemTime) <= 300000]]]' -MaxEvents 100 -ErrorAction Stop
    $Results = $Event | ForEach-Object -Process {

        $SubjectUserName = Get-EventDataValue -Event $_ -Name "SubjectUserName"
        $SubjectDomainName = Get-EventDataValue -Event $_ -Name "SubjectDomainName"
        $SubjectLogonId = Get-EventDataValue -Event $_ -Name "SubjectLogonId"
        $NewProcessName = Get-EventDataValue -Event $_ -Name "NewProcessName"
        $CommandLine = Get-EventDataValue -Event $_ -Name "CommandLine"
        $ParentProcessName = Get-EventDataValue -Event $_ -Name "ParentProcessName"
        $TokenElevationType = Get-EventDataValue -Event $_ -Name "TokenElevationType"

        If (($MonitorAdmins -Contains $SubjectUserName) -And ($TokenElevationType -ne "%%1938")) {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, AdminUser, Domain, LogonID, MachineName, Process, ParentProcess, CommandLine, TokenElevationType, Date, Message
            $Obj.EventID = $_.Id
            $Obj.AdminUser = $SubjectUserName
            $Obj.Domain = $SubjectDomainName
            $Obj.LogonID = $SubjectLogonId
            $Obj.MachineName = $_.MachineName
            $Obj.Process = $NewProcessName
            $Obj.ParentProcess = $ParentProcessName
            $Obj.CommandLine = $CommandLine
            $Obj.TokenElevationType = $TokenElevationType
            $Obj.Date = $_.TimeCreated
            $Obj.Message = "A monitored administrator account executed an elevated process"

            Write-Output -InputObject $Obj

        }  # End If

    }  # End ForEach-Object

    If ($Results) {

        $Css = @"
<style>
table {
    font-family: verdana,arial,sans-serif;
    font-size:11px;
    color:#333333;
    border-width: 1px;
    border-color: #666666;
    border-collapse: collapse;
}
th {
    border-width: 1px;
    padding: 8px;
    border-style: solid;
    border-color: #666666;
    background-color: #dedede;
}
td {
    border-width: 1px;
    padding: 8px;
    border-style: solid;
    border-color: #666666;
    background-color: #ffffff;
}
</style>
"@ # End CSS

        $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
        $PreContent = "<h2>NOTIFICATION: Monitored Administrator Account Executed An Elevated Process</h2><p>The below table contains information about elevated process activity.</p>"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font></p>"
        $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent | Out-String
        Try {
            Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Monitored Admin Executed Elevated Process" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -UseSsl -Port 587 -Credential $Credential -ErrorAction Stop
        } Catch {
            Throw "Failed To Send Elevated Process Alert. $($_.Exception.Message)"
        }  # End Try Catch

    }  # End If

} Catch {

    Throw "Failed To Query Elevated Process Events. $($_.Exception.Message)"

}  # End Try Catch
