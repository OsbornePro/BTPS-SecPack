#Requires -Version 3.0
# Alert IT when a users password is changed
$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4723 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1 -ErrorAction SilentlyContinue
$Results = $Event | ForEach-Object -Process {

    $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, User, TargetDomain, MachineName, SID, Date, Message
    $Obj.EventID = $_.Id
    $Obj.User = $_.Properties[0].Value
    $Obj.TargetDomain = $_.Properties[1].Value
    $Obj.MachineName = $_.MachineName
    $Obj.SID = $_.Properties[2].Value
    $Obj.Date = $_.TimeCreated
    $Obj.Message = "An attempt was made to change an account password"
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

    $PreContent = "<h2>NOTIFICATION: A Password Change Has Been Attempted</h2><p>The below table contains information on a password change attempt.</p>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font></p>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent | Out-String
    Try {
        Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Password Change Attempt" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587 -ErrorAction Stop
    } Catch {
        Throw "Failed To Send Password Change Alert. $($_.Exception.Message)"
    }  # End Try Catch

}  # End If
