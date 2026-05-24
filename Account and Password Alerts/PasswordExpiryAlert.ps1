#Requires -Version 3.0
#Requires -Modules ActiveDirectory
# Alerts IT admins and users who have expiring or expired passwords. This needs to be run on a Domain Controller and works best when set up as a task

[Int32]$DaysBeforeExpiration = 15
[Int32]$MaxPassAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
$RootDSE = Get-ADRootDSE -Server $env:USERDNSDOMAIN
$PasswordPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property minPwdAge, maxPwdAge, minPwdLength, pwdHistoryLength, pwdProperties

$Policy = $PasswordPolicy | Select-Object -Property @{
    Name = "PolicyType"
    Expression = { "Password" }
}, @{
    Name = "maxPwdAge"
    Expression = { "$($_.maxPwdAge / -864000000000) days" }
}, minPwdLength, pwdHistoryLength, @{
    Name = "pwdProperties"
    Expression = {
        Switch ($_.pwdProperties) {
            0 { "Passwords can be simple and the administrator account cannot be locked out" }
            1 { "Passwords must be complex and the administrator account cannot be locked out" }
            8 { "Passwords can be simple, and the administrator account can be locked out" }
            9 { "Passwords must be complex, and the administrator account can be locked out" }
            Default { $_.pwdProperties }
        }  # End Switch
    }
}

$PolicyString = (("Max Password Age: $($Policy.maxPwdAge)<br>`nPassword History: $($Policy.pwdHistoryLength)<br>`nMinimum Password Length: $($Policy.minPwdLength)") | Out-String).Trim()
[String]$EnvDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
[DateTime]$TodaysDate = Get-Date

[Array]$UserDetails = Get-ADUser -Filter { Enabled -eq $True -and PasswordNeverExpires -eq $False } -Properties DisplayName, Mail, PasswordLastSet, PasswordNeverExpires | Where-Object -FilterScript { $_.PasswordLastSet -ne $Null } | Select-Object -Property DisplayName, Mail, SamAccountName, @{
        Label = "ExpiryDate"
        Expression = { $_.PasswordLastSet.AddDays($MaxPassAge) }
    }
[Array]$ExpiredPasswords = @()
[Array]$ExpiringSoon = @()

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

ForEach ($Users in $UserDetails) {

    $ExpirationDate = $Users.ExpiryDate
    $DaysLeft = ($ExpirationDate - $TodaysDate).Days
    $Recipient = $Users.Mail
    If ([String]::IsNullOrWhiteSpace($Recipient)) {
        Write-Warning -Message "Skipping $($Users.SamAccountName). No email address found."
        Continue
    }  # End If

    If ($ExpirationDate -lt $TodaysDate) {

        $ExpiredPasswords += $Users
        $ToWhom = $Users.DisplayName
        $PreContent1 = "<h2>ALERT: Password Has Expired</h2>"
        $NoteLine1 = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss') from IT as a friendly reminder."
        $PostContent1 = "<br><p><font size='2'><i>$NoteLine1</i></font></p>"

        $MailBody1 = $Users | ConvertTo-Html -Head $Css -PostContent $PostContent1 -PreContent $PreContent1 -Body "Attention $ToWhom, <br>
<br>
If you have received this email your sign in password has expired.<br>
<br>
You can reset your password using the following link: <a href='https://aka.ms/sspr'>HERE</a><br>
<br>
If you are in the office on a company device press <strong>(Ctrl + Alt + Del)</strong> and click the <strong>`"Change Password`"</strong> button. If you are using the VPN you will need to connect to the VPN before changing your password.<br>
<br>
<strong>Password Policy</strong><br>
$PolicyString<br>
<br>
<hr>
<br>" | Out-String

        Try {
            Send-MailMessage -From FromEmail -To $Recipient -Subject "ACTION REQUIRED: Your Password Has Expired" -BodyAsHtml -Body $MailBody1 -SmtpServer UseSmtpServer -Priority High -UseSSL -Port 587 -Credential $Credential -ErrorAction Stop
        } Catch {
            Send-MailMessage -From FromEmail -To ToEmail -Subject "Forward This Email Alert To $Recipient. Auto Send Failed" -BodyAsHtml -Body $MailBody1 -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential
        }  # End Try Catch

    } ElseIf (($TodaysDate -ge $ExpirationDate.AddDays(-$DaysBeforeExpiration)) -And ($TodaysDate -le $ExpirationDate)) {

        $ExpiringSoon += $Users
        $ToWho = $Users.DisplayName
        $PreContent = "<h2>Password Expiring In $DaysBeforeExpiration Days Or Less</h2>"
        $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss') from IT as a friendly reminder."
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font></p>"
        $MailBody = $Users | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "Attention $ToWho, <br>
<br>
Your password <strong>EXPIRES IN $DaysLeft DAYS</strong> on <strong>$($ExpirationDate.ToLongDateString())</strong>. Reset your password before it expires.<br>
<br>
<a href=`"https://haveibeenpwned.com/Passwords`">Verify Your New Password Has Never Been Exposed</a><br>
<a href=`"https://bitwarden.com/password-strength/`">Password Strength Checker</a><br>
<br>
<strong>Password Policy</strong><br>
$PolicyString<br>
<br>
<h4>How Do I Change My Password?</h4>
<ol>
    <li>Make sure you can access a company shared drive. If you can view the contents of a company network share you can change your password.</li>
    <li>Come up with a password following the rules of our password policy above.</li>
    <li>Press <strong>Ctrl+Alt+Del</strong> and click the `"<strong>Change Password</strong>`" button.</li>
    <li>Enter your current password on the first line and your new password on the second and third lines.</li>
</ol>
<h4>How Do I Change My Password Without A Computer?</h4>
You are able to change your password at the following link: <a href='https://aka.ms/sspr'>HERE: Change Password Link</a><br>
<br>
<hr>
<br>" | Out-String

        Try {

            Send-MailMessage -From FromEmail -To $Recipient -Subject "ACTION REQUIRED: Your $EnvDomain Password Is Expiring Soon" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -Priority Normal -UseSSL -Port 587 -Credential $Credential -ErrorAction Stop

        } Catch {

            Send-MailMessage -From FromEmail -To ToEmail -Subject "Forward This Email To $Recipient. Auto Send Failed" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential

        }  # End Try Catch

    }  # End If ElseIf

}  # End ForEach

If ($ExpiredPasswords) {

    $PreContentExpired = "<h2>Users Whose Passwords Have Expired</h2>"
    $PostContentExpired = "<br><p><font size='2'><i>This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')</i></font></p>"
    $MBody1 = $ExpiredPasswords | ConvertTo-Html -Head $Css -PostContent $PostContentExpired -PreContent $PreContentExpired -Body "FYI, <br><br>The below table contains info on the users who have received a password expired notification.<br><br><hr><br>" | Out-String
    Try {
        Send-MailMessage -From FromEmail -To ToEmail -Subject "Users Whose Passwords Have Expired" -BodyAsHtml -Body $MBody1 -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential -ErrorAction Stop
    } Catch {
        Throw "Failed To Send Expired Password Summary Alert. $($_.Exception.Message)"
    }  # End Try Catch

}  # End If

If ($ExpiringSoon) {

    $PreContentExpiring = "<h2>Users Who Received Password Expiring Notifications</h2>"
    $PostContentExpiring = "<br><p><font size='2'><i>This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')</i></font></p>"
    $MBody = $ExpiringSoon | ConvertTo-Html -Head $Css -PostContent $PostContentExpiring -PreContent $PreContentExpiring -Body "FYI, <br><br>The below table contains info on the users who have received a password expiring notification.<br><br><hr><br>" | Out-String
    Try {
        Send-MailMessage -From FromEmail -To ToEmail -Subject "Users Who Received Password Expiring Notifications" -BodyAsHtml -Body $MBody -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential -ErrorAction Stop
    } Catch {
        Throw "Failed To Send Expiring Password Summary Alert. $($_.Exception.Message)"
    }  # End Try Catch

}  # End If
