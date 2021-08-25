# This is an alert for IT whenever an account Expires
$Accounts = Search-ADAccount -AccountExpiring -TimeSpan "10.00:00:00" | Select-Object -Property AccountExpirationDate, Name, @{
                                                                                                   Label = "Manager"
                                                                                                   E = { (Get-Aduser(Get-AdUser $_ -Property Manager).Manager).Name }
                                                                                                   } # End Properties

If ($Accounts) {

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
"@

    $PreContent = "<Title>Expiring Users (Next 10 Days)</Title>"
    $NoteLine = "$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
    $Body = $Accounts | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "The below table displays accounts that are expiring soon."  | Out-String

    Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Accounts Expiring" -BodyAsHtml -Body $Body -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587

} # End If
