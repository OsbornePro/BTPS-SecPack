# Alert IT when a users password is changed by another account
$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4724 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1

$Results = $Event | ForEach-Object {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, EffectedUser, ExecutingUser, MachineName, Date, Message
            $Obj.EventID = $_.Id
            $Obj.EffectedUser = $_.Properties[0].Value
            $Obj.ExecutingUser = $_.Properties[4].Value
            $Obj.MachineName = $_.MachineName
            $Obj.Date = $_.TimeCreated
            $Obj.Message = "An attempt was made to change an account password"

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

    $PreContent = "<Title>NOTIFICATION: A Password Change Has Been Attempted on one account from a different account</Title>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on a user whose password was attempted to be changed by another user.<br><br><hr><br><br>" | Out-String

    Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: User Attempted to Change Other Users Password" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587

}  # End If
