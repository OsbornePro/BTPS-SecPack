#Requires -Version 3.0
# Alert IT when an account is locked out.

$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4740 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1 -ErrorAction SilentlyContinue
$Results = $Event | ForEach-Object -Process {

    $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, LockedOutUser, UserSID, CallerComputerName, DC, Date, Message

    $Obj.EventID = $_.Id
    $Obj.LockedOutUser = $_.Properties[0].Value
    $Obj.UserSID = $_.Properties[2].Value
    $Obj.CallerComputerName = $_.Properties[1].Value
    $Obj.DC = $_.MachineName
    $Obj.Date = $_.TimeCreated
    $Obj.Message = "A user account was locked out"

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

    $PreContent = "<h2>NOTIFICATION: A User Account Has Been Locked Out</h2><p>The below table contains information on the user account that was locked out.</p>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font></p>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent | Out-String

    Try {

        Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Account Lockout" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential -ErrorAction Stop

    } Catch {

        Throw "Failed To Send Account Lockout Alert. $($_.Exception.Message)"

    }  # End Try Catch

}  # End If
