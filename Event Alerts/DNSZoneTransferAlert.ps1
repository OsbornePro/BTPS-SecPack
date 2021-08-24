$Event = Get-WinEvent -FilterHashtable @{LogName='DNS Server';ID='6001'} -MaxEvents 1
If ($Event) {

    $Results = $Event | ForEach-Object {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, Domain, InitiatedBy, DC, Date, Message
            $Obj.EventID = $_.Id
            $Obj.Domain = $_.Properties[1].Value
            $Obj.InitiatedBy = $_.Properties[2].Value
            $Obj.DC = $_.MachineName
            $Obj.Date = $_.TimeCreated
            $Obj.Message = "DNS Zone Transfer has occured"

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

        $PreContent = "<Title>DNS Zone Transfer</Title>"
        $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
        $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>A DNS Zone transfer has occured. Details are below.<br><br><hr><br><br>" | Out-String

        Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: DNS Zone Transfer Occured" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -UseSsl -Port 587 -Credential $Credential

    }  # End If

}  # End Else
