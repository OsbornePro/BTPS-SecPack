Write-Verbose "Importing MSOnline cmdlets..."
Import-Module MSOnline

Write-Verbose "Connecitng to Azure AD modules"
Connect-MsolService -Credential $Cred

$ExoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Cred -AllowRedirection -Authentication Basic

Import-PSSession -Session $ExoSession

$UserInboxRules = @()
$UserDelegates = @()
$AllUsers = @()
$AllUsers = Get-MsolUser -All -EnabledFilter EnabledOnly | Where-Object { ($_.UserPrincipalName -notlike "*#EXT#*") } | Select-Object -Property ObjectID, UserPrincipalName, FirstName, LastName, StrongAuthenticationRequirements, StsRefreshTokensValidFrom, StrongPasswordRequired, LastPasswordChangeTimestamp

ForEach ($User in $AllUsers) {

    Write-Output "Checking inbox rules and delegates for user: " $User.UserPrincipalName

    $UserInboxRules += Get-InboxRule -Mailbox $User.UserPrincipalname | Where-Object { ($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.RedirectsTo -ne $null) } | Select-Object -Property Name, Description, Enabled, Priority, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage

    $UserDelegates += Get-MailboxPermission -Identity $User.UserPrincipalName | Where-Object { ($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*") }

} # End ForEach

$SMTPForwarding = Get-Mailbox -ResultSize Unlimited | Select-Object -Property DisplayName,ForwardingAddress,ForwardingSMTPAddress,DeliverToMailboxandForward | Where-Object {$_.ForwardingSMTPAddress -ne $null}

New-Item -ItemType Directory -Path C:\Users\Public\Office365 -ErrorAction SilentlyContinue | Out-Null

$UserInboxRules | Export-Csv "C:\Users\Public\Office365\MailForwardingRulesToExternalDomains.csv"
$UserDelegates | Export-Csv "C:\Users\Public\Office365\MailboxDelegatePermissions.csv"
$SMTPForwarding | Export-Csv "C:\Users\Public\Office365\Mailboxsmtpforwarding.csv"
$Attach = "C:\Users\Public\Office365\Mailboxsmtpforwarding.csv", "C:\Users\Public\Office365\MailboxDelegatePermissions.csv", "C:\Users\Public\Office365\MailForwardingRulesToExternalDomains.csv"

Try {

    Send-MailMessage -From $From -To $To -Attachments $Attach -Priority Normal -Subject 'Weekly Check Office365 Mailbox Forwarding Rules' -Body 'Microsoft suggests reviewing this information once a week to ensure Outlooks forwarding rules are not configured in a malicious or unusual manner.' -SmtpServer $SmtpServer

} # End Try
Catch {

    ForEach ($Report in $Attach) {

        Send-MailMessage -From FromEmail -To ToEmail -Attachments $Report -Priority Normal -Subject 'Weekly Check Office365 Mailbox Forwarding Rules' -Body 'Microsoft suggests reviewing this information once a week to ensure Outlooks forwarding rules are not configured in a malicious or unusual manner.' -SmtpServer UseSmtpServer -Credential $Credential -UseSsl -Port 587  -Credential $Credential

    } # End ForEach

} # End Catch

Get-ChildItem -Path 'C:\Users\Public\Office365' -Include "*.csv" -Recurse | Remove-Item
Remove-PsSession -Session $ExoSession
