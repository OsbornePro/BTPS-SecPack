#Requires -Version 3.0
# This alert is used to alert IT when a failed password attempt occurs on a server

$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 120000]]]' -MaxEvents 1 -ErrorAction SilentlyContinue
$Results = $Event | ForEach-Object -Process {

    $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, User, Device, DC, LogonType, Date, Message

    $Obj.EventID = $_.Id
    $Obj.User = $_.Properties[5].Value
    $Obj.Device = $_.Properties[6].Value
    $Obj.DC = $_.MachineName
    $Obj.LogonType = $_.Properties[10].Value
    $Obj.Date = $_.TimeCreated
    $Obj.Message = "An account failed to log on"

    Write-Output -InputObject $Obj

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

    $PreContent = "<h2>NOTIFICATION: Failed Logon Attempt Detected</h2><p>The below table contains information about a failed logon attempt.</p>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font></p>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent | Out-String

    Try {
        Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Failed UserName And Password $env:COMPUTERNAME" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587 -ErrorAction Stop
    } Catch {
        Throw "Failed To Send Failed Logon Alert. $($_.Exception.Message)"
    }  # End Try Catch

}  # End If
