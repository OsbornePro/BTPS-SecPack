$Events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=4741;StartTime=(Get-Date).AddHours("-1")} | Select-Object -First 1
$Results = $Events | ForEach-Object {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, UserName, DomainName, MachineName, Date, Message
            $Obj.EventID = $_.Id
            $Obj.UserName = $_.Properties[0].Value
            $Obj.DomainName = $_.Properties[1].Value
            $Obj.MachineName = $_.Properties[26].Value
            $Obj.Date = $_.TimeCreated
            $Obj.Message = "A new computer object was created"

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

    $PreContent = "<Title>NOTIFICATION: A New Computer Object was Added to Domain</Title>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on a new computer object that was added to the domain.<br><br><hr><br><br>" | Out-String

    Send-MailMessage -From FromEamil -To ToEmail -Subject "AD Event: New Computer Added" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587

}  # End If
