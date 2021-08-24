# Alert IT when an account is locked out.
$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4740 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1

$Results = $Event | ForEach-Object {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, User, MachineName, ProcessID, SID, Date, Message
            $Obj.EventID = $_.Id
            $Obj.User = $_.Properties[0].Value
            $Obj.MachineName = $_.MachineName
            $Obj.ProcessID = $_.ProcessID
            $Obj.SID = $_.Properties[2].Value
            $Obj.Date = $_.TimeCreated
            $Obj.Message = "A user account was locked out"

            $Obj

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

    $PreContent = "<Title>NOTIFICATION: A User Account has been Locked Out</Title>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on the user whose account was locked out.<br><br><hr><br><br>" | Out-String

   Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Account Lockout" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential

}  # End If
