#Requires -Version 3.0
#Requires -Modules ActiveDirectory
# This is an alert for IT whenever an account Expires
$Accounts = Search-ADAccount -UsersOnly -AccountExpiring -TimeSpan "10.00:00:00" | `
    Get-ADUser -Properties AccountExpirationDate, Manager | Select-Object -Property AccountExpirationDate, Name, SamAccountName, @{
        Label = "Manager"
        E = {
            If ($_.Manager) {
                Try {
                    (Get-ADUser -Identity $_.Manager -Properties DisplayName -ErrorAction Stop).DisplayName
                } Catch {
                    Write-Output -InputObject "Manager Lookup Failed"
                }  # End Try Catch
            } Else {
                Write-Output -InputObject "No Manager Listed"
            }  # End If Else
        }  # End E
    } | Sort-Object -Property AccountExpirationDate

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

    $PreContent = "<h2>Expiring Users (Next 10 Days)</h2><p>The below table displays accounts that are expiring soon.</p>"
    $NoteLine = "$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font></p>"
    $Body = $Accounts | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent | Out-String
    Try {
        Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Accounts Expiring" -BodyAsHtml -Body $Body -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587 -ErrorAction Stop
    } Catch {
        Throw "Failed To Send Expiring Account Alert. $($_.Exception.Message)"
    }  # End Try Catch

} # End If
