# Alerts IT admins and the users who have expiring or expired passwords. This needs to be run on a Domain Controller and works best when set up as a task

[Int32]$MaxPassAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
$RootDSE = Get-ADRootDSE -Server $env:USERDNSDOMAIN
$PasswordPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property minPwdAge, maxPwdAge, minPwdLength, pwdHistoryLength, pwdProperties
$Policy =  $PasswordPolicy | Select @{n="PolicyType";e={"Password"}},`
                              @{n="maxPwdAge";e={"$($_.maxPwdAge / -864000000000) days"}},`
                              minPwdLength,`
                              pwdHistoryLength,`
                              @{n="pwdProperties";e={Switch ($_.pwdProperties) {
                                  0 {"Passwords can be simple and the administrator account cannot be locked out"}
                                  1 {"Passwords must be complex and the administrator account cannot be locked out"}
                                  8 {"Passwords can be simple, and the administrator account can be locked out"}
                                  9 {"Passwords must be complex, and the administrator account can be locked out"}
                                  Default {$_.pwdProperties}}}}
$PolicyString = "Max Password Age: $($Policy.maxPwdAge)<br>`nPassword History: $($Policy.pwdHistoryLength)<br>`nMinimum Password Length: $($Policy.minPwdLength)"
[String]$EnvDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
[DateTime]$TodaysDate = Get-Date
[Array]$UserDetails = Get-ADUser -Filter { Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties * | Select-Object -Property "Displayname","Mail", @{l="ExpiryDate";e={$_.PasswordLastSet.AddDays($MaxPassAge)}}
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
    $DaysLeft = ($ExpirationDate - (Get-Date)).Days | Out-String
    
    If ($ExpirationDate -ge $TodaysDate) {

        $ExpiredPasswords += $Users
        $ToWhom = $Users.DisplayName

        $PreContent1 = "<Title>ALERT: Password Has Expired</Title>"
        $NoteLine1 = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss') from IT as a friendly reminder."
        $PostContent1 = "<br><p><font size='2'><i>$NoteLine1</i></font>"
        $MailBody1 = $Users | ConvertTo-Html -Head $Css -PostContent $PostContent1 -PreContent $PreContent1 -Body "Attention $ToWhom, <br>
<br>
If you have received this email your sign in password has expired.<br>
<br>
You can reset your password using the following link: <a href='https://account.activedirectory.windowsazure.com/ChangePassword.aspx?BrandContextID=O365&ruO365='>HERE</a><br>
<br>If you are in the office on a company device press <strong>(Ctrl + Alt + Del)</strong> and click the <strong>`"Change Password`"</strong> button. If you are using the VPN you will need to connect to the VPN before changing your password. <br>
<br>
<strong>Password Policy</strong><br>
$PolicyString<br>
<br>
<hr>
<br>" | Out-String

        # Alerts IT by sending an email
        $From1 = $Users.Mail | Out-String

        Try {

            Send-MailMessage -From FromEmail -To $From1 -Subject "ACTION REQUIRED: Your Password Has Expired" -BodyAsHtml -Body $MailBody1 -SmtpServer UseSmtpServer -Priority High -UseSSL -Port 587 -Credential $Credential

        } # End Try
        Catch {

            Send-MailMessage -From FromEmail -To $From1 -Subject "ACTION REQUIRED: Your Password Has Expired" -BodyAsHtml -Body $MailBody1 -SmtpServer UseSmtpServer -Priority High -UseSSL -Port 587 -Credential $Credential
            Send-MailMessage -From FromEmail -To ToEmail -Subject "Forward This Email Alert to $From1. Auto Send Failed" -BodyAsHtml -Body $MailBody1 -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential

        } # End Catch

    } # End if

    If (($TodaysDate -ge $ExpirationDate.AddDays(-15)) -and ($TodaysDate -le $ExpirationDate)) {

        $ExpiringSoon += $Users
        $ToWho = $Users.DisplayName

        $PreContent = "<Title>Password Expiring in 15 days or less</Title>"
        $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss') from IT as a friendly reminder."
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
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
    <li>Make sure you can access a company shared drive. If you can view the contents of a company network share you can change your password</li>
    <li>Come up with a password following the rules of our password policy above</li>
    <li>Press <strong>Ctrl+Alt+Del</strong> and click the `"<strong>Change Password</strong>`" Button</li>
    <li>Enter your current password on the first line and your new password on the second and third lines</li>
</ol>
<h4>How Do I Change my Password Wihtout a Computer?</h4>
 <strong>You are able to change your password at the following link: <a href='https://account.activedirectory.windowsazure.com/ChangePassword.aspx?BrandContextID=O365&ruO365='>HERE: Change Password Link</a> <br>
 <br>
<hr><br>" | Out-String

        $From = $Users.Mail | Out-String

        Try {

            Send-MailMessage -From FromEmail -To $From1 -Subject "ACTION REQUIRED: Your $EnvDomain Password is Expiring Soon" -BodyAsHtml -Body $MailBody -SmtpServer UseSmptServer -Priority Normal -UseSSL -Port 587 -Credential $Credential

        } # End Try
        Catch {

            Send-MailMessage -From FromEmail -To $From1 -Subject "ACTION REUQIRED: Your $EnvDomain Password is Expiring Soon" -BodyAsHtml -Body $MailBody -SmtpServer UseSmptServer -Priority Normal -UseSSL -Port 587 -Credential $Credential
            Send-MailMessage -From FromEmail -To ToEmail -Subject "Forward This email to $From1. Auto Send Failed" -BodyAsHtml -Body $MailBody -SmtpServer UseSmptServer -UseSSL -Port 587 -Credential $Credential

        } # End Catch

    } # End Elseif
    Else {

        Write-Output "[*] No passwords expiring in the next 14 days or less."

    } # End Else

} # End Foreach


If ($ExpiredPasswords) {

    $MBody1 = $ExpiredPasswords | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "FYI, <br><br>The below table contains info on the users who have received a password has expired notification.<br><br><hr><br>" | Out-String
    Send-MailMessage -From FromEmail -To ToEmail -Subject "Users Whos Passwords Have Expired" -BodyAsHtml -Body $MBody1 -SmtpServer UseSmtpServer -UseSSL -Port 587 -Credential $Credential

} # End if


If ($ExpiringSoon) {

    $MBody = $ExpiringSoon | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "FYI, <br><br>The below table contains info on the users who have received a password exipring notification.<br><br><hr><br>" | Out-String
    Send-MailMessage -From FromEmail -To ToEmail -Subject "Users Who Received Password Expiring Notifications" -BodyAsHtml -Body $MBody -SmtpServer UseSmptServer -UseSSL -Port 587 -Credential $Credential

} # End If
