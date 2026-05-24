#Requires -Version 3.0
Function Find-DNSZoneTransferEvent {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]  # End Parameter
        [PSCredential]$Credential,

        [Parameter(
            Mandatory=$True,
            Position=1
        )]  # End Parameter
        [String]$SmtpServer,

        [Parameter(
            Mandatory=$True,
            Position=2
        )]  # End Parameter
        [String]$FromEmail,

        [Parameter(
            Mandatory=$True,
            Position=3
        )]  # End Parameter
        [String]$ToEmail
    )  # End Param

    Try {

        Write-Verbose -Message "[*] Searching DNS Server Event Log For Event ID 6001"
        $Event = Get-WinEvent -FilterHashtable @{
                LogName='DNS Server'
                ID='6001'
        } -MaxEvents 1 -ErrorAction Stop

    } Catch {
        Write-Output -InputObject "[x] Failed Searching DNS Server Event Log"
        Write-Output -InputObject $_
        Return
    }  # End Try Catch

    If ($Event) {

        Write-Verbose -Message "[*] Building DNS Zone Transfer Event Object"
        $Results = $Event | ForEach-Object -Process {
            [PSCustomObject]@{
                EventID     = $_.Id
                Domain      = $_.Properties[1].Value
                InitiatedBy = $_.Properties[2].Value
                DC          = $_.MachineName
                Date        = $_.TimeCreated
                Message     = "DNS Zone Transfer has occurred"
            }  # End PSCustomObject
        }  # End ForEach-Object

        If ($Results) {

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
"@ # End CSS

            Write-Verbose -Message "[*] Generating Email Body"
            $PreContent = "<Title>DNS Zone Transfer</Title>"
            $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
            $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
            $MailBody = $Results |
                ConvertTo-Html `
                    -Head $Css `
                    -PostContent $PostContent `
                    -PreContent $PreContent `
                    -Body "<br>A DNS Zone Transfer has occurred. Details are below.<br><br><hr><br><br>" |
                Out-String

            Try {

                Send-MailMessage `
                    -From $FromEmail `
                    -To $ToEmail `
                    -Subject "AD Event: DNS Zone Transfer Occurred" `
                    -BodyAsHtml `
                    -Body $MailBody `
                    -SmtpServer $SmtpServer `
                    -UseSsl `
                    -Port 587 `
                    -Credential $Credential `
                    -ErrorAction Stop
                Write-Verbose -Message "[*] Email Sent"

            } Catch {
                Write-Output -InputObject "[x] Failed Sending DNS Zone Transfer Email"
                Write-Output -InputObject $_
            }  # End Try Catch
        }  # End If

    } Else {
        Write-Verbose -Message "[*] No DNS Zone Transfer Event Was Found"
    }  # End If Else

}  # End Function Find-DNSZoneTransferEvent
