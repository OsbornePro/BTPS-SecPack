$Event = Get-EventLog -LogName Security -InstanceId 4625 -Newest 1 

$MailBody= $Event.Message + "`r`n`t" + $Event.TimeGenerated | Format-List -property * | Out-String

Send-MailMessage -from $From -To $To -Subject "AD Event: Failed UserName and Password $env:COMPUTERNAME" -Body $MailBody -SmtpServer $SmtpServer

