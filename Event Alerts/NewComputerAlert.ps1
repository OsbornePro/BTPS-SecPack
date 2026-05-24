Function Get-NewComputerObject {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0)]
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
        [String]$ToEmail,

        [Parameter(
            Mandatory=$False,
            Position=4
        )]  # End Parameter
        [Int]$HoursBack = 1
    )  # End Param

    Try {

        Write-Verbose -Message "[*] Searching Security Event Log For Event ID 4741"
        $Events = Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 4741
                StartTime = (Get-Date).AddHours(-$HoursBack)
            } -ErrorAction Stop | Select-Object -First 1

    } Catch {
        Write-Output -InputObject "[x] Failed Searching Security Event Log"
        Write-Output -InputObject $_
        Return
    }  # End Try Catch

    $Results = $Events | ForEach-Object -Process {

        [PSCustomObject]@{
            EventID     = $_.Id
            UserName    = $_.Properties[0].Value
            DomainName  = $_.Properties[1].Value
            MachineName = $_.Properties[26].Value
            Date        = $_.TimeCreated
            Message     = "A new computer object was created"
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

        Write-Verbose -Message "[*] Building Email Body"
        $PreContent = "<Title>NOTIFICATION: A New Computer Object was Added to Domain</Title>"
        $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
        $MailBody = $Results | ConvertTo-Html `
                        -Head $Css `
                        -PostContent $PostContent `
                        -PreContent $PreContent `
                        -Body "<br>The below table contains information on a new computer object that was added to the domain.<br><br><hr><br><br>" | Out-String

        Try {

            Send-MailMessage `
                -From $FromEmail `
                -To $ToEmail `
                -Subject "AD Event: New Computer Added" `
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

    } Else {
        Write-Verbose -Message "[*] No New Computer Object Events Were Found"
    }  # End If Else

}  # End Function Get-NewComputerObject
