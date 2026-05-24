<#
.SYNOPSIS
This cmdlet is for identifying when an unusual service is being run, possibly indicating credentials were compromised.


.DESCRIPTION
This is best used as a task that runs in response to Event ID 7009 or 7045.
The newest matching System events are collected and sent to administrators as an HTML email alert.
Windows Defender definition update service events are excluded to reduce noise.


.PARAMETER SmtpServer
Defines the SMTP server used to send the alert email.

.PARAMETER To
Defines the email address receiving the alert.

.PARAMETER From
Defines the email address sending the alert.

.PARAMETER Credential
Defines the PSCredential object used to authenticate to the SMTP server.


.EXAMPLE
PS> Get-NewlyInstalledService `
    -SmtpServer mail.smtp2go.com `
    -To alert@osbornepro.com `
    -From alerter@osbornepro.com `
    -Credential (Get-Credential) `
    -Verbose
# This example sends an alert email when matching service-related event IDs are discovered.


.INPUTS
None.


.OUTPUTS
None.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://osbornepro.com
#>
Function Get-NewlyInstalledService {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="Enter an SMTP Server to use. Example: mail.smtp2go.com"
            )]  # End Parameter
            [String]$SmtpServer,
    
            [Parameter(
                Mandatory=$True,
                Position=1,
                HelpMessage="Enter an email address to send the alert to. Example: alert@osbornepro.com"
            )]  # End Parameter
            [String]$To,
    
            [Parameter(
                Mandatory=$True,
                Position=2,
                HelpMessage="Enter an email address to send the alert from. Example: alert@osbornepro.com"
            )]  # End Parameter
            [String]$From,
    
            [Parameter(
                Mandatory=$True,
                Position=3
            )]  # End Parameter
            [PSCredential]$Credential,
    
            [Parameter(
                Mandatory=$False,
                Position=4
            )]  # End Parameter
            [Int]$MaxEvents = 2
        )  # End param

    BEGIN {

        Write-Verbose -Message "[*] Pulling Events In Question"
        Try {

            $EventInfo = Get-WinEvent -FilterHashtable @{
                    LogName = "System"
                    ID      = 7009,7045
                } -MaxEvents $MaxEvents -ErrorAction Stop

        } Catch {
            Write-Output -InputObject "[x] Failed Pulling Events In Question"
            Write-Output -InputObject $_
            Return
        }  # End Try Catch

    } PROCESS {

        If (!($EventInfo)) {
            Write-Verbose -Message "[*] No Matching Events Were Found"
            Return
        }  # End If

        Write-Verbose -Message "[*] Filtering Windows Defender Definition Update Events"
        $EventInfo = $EventInfo | Where-Object -FilterScript {
            $_.Message -notlike "*Service File Name:  C:\ProgramData\Microsoft\Windows Defender\Definition Updates\*"
        }  # End Where-Object

        If (!($EventInfo)) {
            Write-Verbose -Message "[*] Only Windows Defender Definition Update Events Were Found"
            Return
        }  # End If
        Write-Verbose -Message "[*] Converting Event Into HTML Viewable Format"

$Css = @"
<style>
table {
    font-family: verdana,arial,sans-serif;
    font-size:11px;
    color:#333333;
    border-width:1px;
    border-color:#666666;
    border-collapse:collapse;
}
th {
    border-width:1px;
    padding:8px;
    border-style:solid;
    border-color:#666666;
    background-color:#dedede;
}
td {
    border-width:1px;
    padding:8px;
    border-style:solid;
    border-color:#666666;
    background-color:#ffffff;
}
</style>
"@

        Write-Verbose -Message "[*] Building Email Mail Body"
        $TableInfo = $EventInfo | Select-Object -Property TimeCreated,Id,ProviderName,ProcessId,UserId,MachineName,Message

        $PreContent = "<Title>MITM Monitoring Alert: Watches for Newly Installed Services</Title>"
        $NoteLine = "$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
        $MailBody = $TableInfo |
                    ConvertTo-Html `
                        -Head $Css `
                        -PostContent $PostContent `
                        -PreContent $PreContent `
                        -Body "If you see BTOBTO, Base64 encoded service names, or random characters for a service name the attacker may have SYSTEM PRIVILEGE. This may also mean admin credentials have been compromised." |
                    Out-String

        Write-Verbose -Message "[*] Creating Email Body And Placing Info Into A Neat Looking Table"
        Try {

            Send-MailMessage `
                -From $From `
                -To $To `
                -Subject "$env:COMPUTERNAME Had New Service Installed" `
                -BodyAsHtml `
                -Body $MailBody `
                -SmtpServer $SmtpServer `
                -Credential $Credential `
                -UseSSL `
                -Port 587 `
                -ErrorAction Stop

            Write-Verbose -Message "[*] Email Sent"

        } Catch {
            Write-Output -InputObject "[x] Failed Sending Email"
            Write-Output -InputObject $_
        }  # End Try Catch

    } END {
    
    }  # End B P E

}  # End Function Get-NewlyInstalledService
