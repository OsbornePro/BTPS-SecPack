#Requires -Version 3.0
# Alert IT when a users password is changed by another account
$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4724 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1 -ErrorAction SilentlyContinue
$Results = $Event | ForEach-Object -Process {

    $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, AffectedUser, ExecutingUser, MachineName, Date, Message

    $Obj.EventID = $_.Id
    $Obj.AffectedUser = If ([String]::IsNullOrWhiteSpace($_.Properties[0].Value)) { $_.Properties[4].Value.Replace('$','') } Else { $_.Properties[0].Value }
    $Obj.ExecutingUser = $_.Properties[4].Value
    $Obj.MachineName = $_.MachineName
    $Obj.Date = $_.TimeCreated

    If ([String]::IsNullOrWhiteSpace($_.Properties[0].Value)) {
        $Obj.Message = "A Computer System account reset its password"
    } ElseIf ($_.Properties[4].Value -Like "MSOL_*") {
        $Obj.Message = "A user used Azure to reset their password"
    } Else {
        $Obj.Message = "An attempt was made to reset an account password"
    }  # End If Else
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

    $PreContent = "<h2>NOTIFICATION: An Account Has Attempted To Reset Another Account Password</h2><p>The below table contains information on a password reset attempt.</p>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font></p>"
    $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent | Out-String
    Try {
        Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: User Attempted To Reset Another Users Password" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587 -ErrorAction Stop
    } Catch {
        Throw "Failed To Send Password Reset Alert. $($_.Exception.Message)"
    }  # End Try Catch

}  # End If
