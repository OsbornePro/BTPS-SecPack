# This alert is used to alert IT when a failed password attempt occurs on a server
$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 120000]]]' -MaxEvents 1

$Results = $Event | ForEach-Object {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, User, Device, DC, Type, Date, Message
            $Obj.EventID = $_.Id
            $Obj.User = $_.Properties[5].Value
            $Obj.Device = $_.Properties[6].Value
            $Obj.DC = $_.MachineName
            $Obj.Type = $_.Properties[12].Value
            $Obj.Date = $_.TimeCreated
            $Obj.Message = "An account failed to log on"

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

    $PreContent = "<Title>NOTIFICATION: A Password Change Has Been Attempted</Title>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on a user whose password was changed.<br><br><hr><br><br>" | Out-String

    Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Failed UserName and Password $env:COMPUTERNAME" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587

}  # End If
