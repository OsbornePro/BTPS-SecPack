#Requires -Version 3.0
# Alert IT when a user account is created

$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4720 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1 -ErrorAction SilentlyContinue
$Results = $Event | ForEach-Object -Process {

    $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, CreatedUser, CreatedUserDomain, CreatedUserSID, ExecutingUser, ExecutingUserDomain, MachineName, Date, Message

    $Obj.EventID = $_.Id
    $Obj.CreatedUser = $_.Properties[0].Value
    $Obj.CreatedUserDomain = $_.Properties[1].Value
    $Obj.CreatedUserSID = $_.Properties[2].Value
    $Obj.ExecutingUser = $_.Properties[4].Value
    $Obj.ExecutingUserDomain = $_.Properties[5].Value
    $Obj.MachineName = $_.MachineName
    $Obj.Date = $_.TimeCreated
    $Obj.Message = "A user account was created"

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

    $PreContent = "<h2>NOTIFICATION: A User Account Has Been Created</h2><p>The below table contains information on a newly created user account.</p>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font></p>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent | Out-String

    Try {
        Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Account Created" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -UseSsl -Port 587 -Credential $Credential -ErrorAction Stop
    } Catch {
        Throw "Failed To Send Account Created Alert. $($_.Exception.Message)"
    }  # End Try Catch

}  # End If
