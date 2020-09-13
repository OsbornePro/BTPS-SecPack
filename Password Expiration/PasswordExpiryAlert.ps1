<#
.DESCRIPTION
  PURPOSE    : Alerts IT admins and the users who have expiring or expired passwords
  REQUIREMENT: This needs to be run on a Domain Controller and works best when set up as a task

.NOTES
  Author : Robert H. Osborne
  Alias  : tobor
  Contact: rosborne@osbornepro.com

.LINKS
  https://roberthosborne.com
  https://osbornepro.com
  https://github.com/tobor88
  https://gitlab.com/tobor88
  https://www.powershellgallery.com/profiles/tobor

#>

# Email Variables
$From = "do-not-reply@$EnvDomain"
$ToAdmin = "it@$EnvDomain"
$SmtpServer = mail.smtp2go.com

# Global variables
[Int32]$MaxPassAge = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.Days
[String]$EnvDomain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
[DateTime]$TodaysDate = Get-Date
[Array]$UserDetails = Get-ADUser -Filter { Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties * | Select-Object -Property "Displayname","Mail", @{l="ExpiryDate";e={$_.PasswordLastSet.AddDays($maxPassAge)}}
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

ForEach ($Users in $UserDetails) 
{

    $ExpirationDate = $Users.ExpiryDate 

    If (($ExpirationDate -eq $TodaysDate) -or ($ExpirationDate -eq $TodaysDate.AddDays(1)) -or ($ExpirationDate -eq $TodaysDate.AddDays(2)))
    {

        $ExpiredPasswords += $Users 

        $ToWhom = $Users.DisplayName

        $PreContent1 = "<Title>ALERT: Password Has Expired</Title>"
        $NoteLine1 = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss') from IT as a friendly reminder."
        $PostContent1 = "<br><p><font size='2'><i>$NoteLine1</i></font>"
        $MailBody1 = $Users | ConvertTo-Html -Head $Css -PostContent $PostContent1 -PreContent $PreContent1 -Body "Attention $ToWhom, <br><br>If you have received this email your sign in password has expired. <br><br>You can reset your password using the following link: <a href='https://account.activedirectory.windowsazure.com/ChangePassword.aspx?BrandContextID=O365&ruO365='>HERE</a> <br><br>If you are in the office on a company device press Ctrl + Alt + Del and click the Change Password button. If you are using the VPN you will need to connect to the VPN before changing your password. <br><br><hr><br>" | Out-String
        
        # Alerts IT by sending an email
        $From1 = $Users.Mail | Out-String

        Try 
        {

            Send-MailMessage -From $From -To $From1 -Subject "ACTION REQUIRED: Your $EnvDomain Password Has Expired" -BodyAsHtml -Body $MailBody1 -SmtpServer $SmtpServer -Priority High
        
        } # End Try

        Catch 
        {

            Send-MailMessage -From $From -To $From1 -Subject "ACTION REQUIRED: Your $EnvDomain Password Has Expired" -BodyAsHtml -Body $MailBody1 -SmtpServer $SmtpServer -Priority High

            Send-MailMessage -From $From -To $ToAdmin -Subject "Forward This Email Alert to $From1. Auto Send Failed" -BodyAsHtml -Body $MailBody1 -SmtpServer $SmtpServer

        } # End Catch
  
    } # End if

    If (($TodaysDate -ge $ExpirationDate.AddDays(-15)) -and ($TodaysDate -le $ExpirationDate)) 
    {

        $ExpiringSoon += $Users 

        $ToWho = $Users.DisplayName

        $PreContent = "<Title>Password Expiring in 15 days or less</Title>"
        $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss') from IT as a friendly reminder."
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
        $MailBody = $Users | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "Attention $ToWho, <br><br>If you have received this email your password is expiring in 15 days or less. Reset your password before it expires. <br><br>If you are on your home internet you can change your password by performing the following steps. <br><br>    <h4>Change Password From Home while connected to the VPN: </h4><strong>1.)</strong> Connect to the VPN. Enter your username and non-expired password. If you are not connected to a VPN or in the office your password change will not take effect and it will cause issues for you. <br>    <strong>2.)</strong> Press Ctrl+Alt+Del and select the 'Change Password' Button. <br>    <strong>3.)</strong> Enter a new password. Your new password needs to be at least 12 characters long and contain a lowercase letter, uppercase letter, and a number or special character. It can also not be one of the top 50 most commonly used passwords. <br><br>If you are changing your password from your desktop or a laptop that does not need to connect to the VPN because it is connected to DirectAccess, the previous rules apply with the execption of Step 1. Do not connect to the VPN on your desktop or a laptop already connected to DirectAccess as you are already on our network. <br><br><strong>NOTE:</strong> Be sure to sign into your laptop while you are in the office after you have changed your password. This is to ensure the laptop is aware your password has changed before you take it home. <br><br><strong>You are also able to change your password without connecting to the VPN at the following link: <a href='https://account.activedirectory.windowsazure.com/ChangePassword.aspx?BrandContextID=O365&ruO365='>HERE: Change Password Link</a> <br><hr><br>" | Out-String

        $From = $Users.Mail | Out-String

        Try 
        {

            Send-MailMessage -From $From -To $From1 -Subject "ACTION REQUIRED: Your $EnvDomain Password is Expiring Soon" -BodyAsHtml -Body $MailBody -SmtpServer $SmptServer -Priority Normal
        
        } # End Try

        Catch 
        {

            Send-MailMessage -From $From -To $From1 -Subject "ACTION REUQIRED: Your $EnvDomain Password is Expiring Soon" -BodyAsHtml -Body $MailBody -SmtpServer $SmptServer -Priority Normal

            Send-MailMessage -From $From -To $ToAdmin -Subject "Forward This email to $From1. Auto Send Failed" -BodyAsHtml -Body $MailBody -SmtpServer $SmptServer

        } # End Catch

    } # End Elseif

    Else 
    {

        Write-Output "[*] No passwords expiring in the next 14 days or less."

    } # End Else
 
} # End Foreach


If ($ExpiredPasswords) 
{

    $MBody1 = $ExpiredPasswords | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "FYI, <br><br>The below table contains info on the users who have received a password has expired notification.<br><br><hr><br>" | Out-String 

    Send-MailMessage -From $From -To $ToAdmin -Subject "Users Whos Passwords Have Expired" -BodyAsHtml -Body $MBody1 -SmtpServer $SmtpServer
  
} # End if
       

If ($ExpiringSoon)
{    
        
    $MBody = $ExpiringSoon | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "FYI, <br><br>The below table contains info on the users who have received a password exipring notification.<br><br><hr><br>" | Out-String 

    Send-MailMessage -From $From -To $ToAdmin -Subject "Users Who Received Password Expiring Notifications" -BodyAsHtml -Body $MBody -SmtpServer $SmptServer

} # End If
