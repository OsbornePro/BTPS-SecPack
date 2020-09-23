# I built this off of a Microsoft suggested script. I will add the link if it is ever sent to me or I find it
#
# This script is used to remediate a compromised Office365 account by performing the Microsoft recommended actions.
#
# The following actions will be performed.
#
#    1.) Reset password (which kills the session).
#
#    2.) Remove mailbox delegates.
#
#    3.) Remove mailforwarding rules to external domains.
#
#    4.) Remove global mailforwarding property on mailbox.
#
#    5.) Set password complexity on the account to be high.
#
#    6.) Enable mailbox auditing.
#
#    7.) Produce Audit Log for the admin to review.

$Upn = Read-Host "What is the user's Email Address/UserPrincipalName Example: first.last@$env:USERDNSDOMAIN"


If ($Null -eq $Upn)
{

    Write-Host "User UPN/email address was not defined was not defined. Ending script" -ForegroundColor Red 

    Break

} # End If
Else
{

    $SamAccountName = $Upn -Split "@"
    
    $TranscriptPath = "C:\Users\Public\Desktop\" + $SamAccountName[0] + "_RemediationTranscript_" + (Get-Date).ToString('MM-dd-yyyy') + ".txt"

    Start-Transcript -Path $TranscriptPath

    Write-Host "$Upn's account will have remediation actions applied to it.`nAn audit report will be saved to $TranscriptPath" -ForegroundColor Cyan

    Import-Module MSOnline

    Write-Verbose "Connecting to Exchange Online Remote Powershell Service"

    $ExoSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential (Get-Credential -Message "Enter Global Admin Creds") -Authentication Basic -AllowRedirection

    If ($Null -ne $ExoSession) 
    { 

        Import-PSSession -Session $ExoSession

    } # End If 
    Else 
    {

        Write-Host "  No EXO service set up for this account" -ForegroundColor Red

    } # End Else 

    Write-Host "Connecting to EOP Powershell Service" -ForegroundColor Cyan

    $EopSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://ps.compliance.protection.outlook.com/powershell-liveid/ -Credential $AdminCredential -Authentication Basic -AllowRedirection

    If ($Null -ne $EopSession) 
    { 

        Import-PSSession -Session $EopSession -AllowClobber

    } # End If
    Else 
    {

        Write-Host "  No EOP service set up for this account" -ForegroundColor Red

    } # End Else

    Connect-MsolService -Credential $AdminCredential

    [Reflection.Assembly]::LoadWithPartialName("System.Web") 

# BELOW THIS LINE CREATES THE FUNCTIONS------------------------------------------------------------------------
Function Get-RandomHexNumber{
    param( 
        [int] $length = 20,
        [string] $chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    )
        $bytes = New-Object "System.Byte[]" $length
        $rnd = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $rnd.GetBytes($bytes)
        $result = ""
        1..$length | foreach{
            $result += $chars[ $bytes[$_] % $chars.Length ]	
        }
        $result
}

$Password = Get-RandomHexNumber -Length 30



Function Reset-Password($Upn) {

    $NewPassword = ([System.Web.Security.Membership]::GeneratePassword(16,2))

    Set-MsolUserPassword –UserPrincipalName $Upn –NewPassword $NewPassword -ForceChangePassword $True

    Write-Host "Password for the user $Upn was changed to $NewPassword. Make sure you record this and share with the user, or be ready to reset the password again. They will have to reset their password on the next logon." -ForegroundColor Cyan 

    Set-MsolUser -UserPrincipalName $Upn -StrongPasswordRequired $True

} # End Function Reset-Password



Function Enable-MailboxAuditing($Upn) {

    Write-Host "Mailbox auditing for user is being enabled..."

    Set-Mailbox $Upn -AuditEnabled $True -AuditLogAgeLimit 365

    Write-Host "Current auditing configuration."    

    Get-Mailbox -Identity $Upn | Select-Object -Property Name, AuditEnabled, AuditLogAgeLimit

} # End Functgion Enable-MailboxAuditing



Function Remove-MailboxDelegates($Upn) {

    Write-Host "Removing Mailbox Delegate Permissions for the affected user $upn." -ForegroundColor Cyan

    $MailboxDelegates = Get-MailboxPermission -Identity $Upn | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}

    Get-MailboxPermission -Identity $Upn | Where-Object {($_.IsInherited -ne "True") -and ($_.User -notlike "*SELF*")}

    ForEach ($Delegate in $MailboxDelegates) 
    {

        Remove-MailboxPermission -Identity $Upn -User $Delegate.User -AccessRights $Delegate.AccessRights -InheritanceType All -Confirm:$False

    } # End ForEach

} # End Function Remove-MailboxDelegates



Function Disable-MailforwardingRulesToExternalDomains($Upn) {

    Write-Host "Disabling mailforwarding rules to external domains for the affected user $Upn."

    Write-Host "Found the following rules that forward or redirect mail to other accounts: "

    Get-InboxRule -Mailbox $Upn | Select-Object -Property Name, Description, Enabled, Priority, ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage, SendTextMessageNotificationTo | Where-Object {(($_.Enabled -eq $True) -and (($_.ForwardTo -ne $Null) -or ($_.ForwardAsAttachmentTo -ne $Null) -or ($_.RedirectTo -ne $Null) -or ($_.SendTextMessageNotificationTo -ne $Null)))} | Format-Table

    Get-InboxRule -Mailbox $Upn | Where-Object {(($_.Enabled -eq $true) -and (($_.ForwardTo -ne $Null) -or ($_.ForwardAsAttachmentTo -ne $Null) -or ($_.RedirectTo -ne $Null) -or ($_.SendTextMessageNotificationTo -ne $Null)))} | Disable-InboxRule -Confirm:$False

    Write-Output "Completed disabling of rules being forwarded to outside domains"

} # Disable Disable-MailforwardingRulesToExternalDomains



Function Remove-MailboxForwarding($Upn) {

    Write-Output "Removing Mailbox Forwarding configurations for the affected user $Upn. Current configuration is:"

    Get-Mailbox -Identity $Upn | Select-Object -Property Name, DeliverToMailboxAndForward, ForwardingSmtpAddress

    Set-Mailbox -Identity $Upn -DeliverToMailboxAndForward $False -ForwardingSmtpAddress $Null

    Write-Host "Mailbox forwarding removal completed. Current configuration is:"

    Get-Mailbox -Identity $Upn | Select-Object -Property Name, DeliverToMailboxAndForward, ForwardingSmtpAddress

} # End Function Remove-MailboxForwarding



Function Get-AuditLog ($Upn) {

    Write-Host "$Upn account has been remediated. There may be things missed. Review the audit transcript for this user to be super-sure you've got everything." -ForegroundColor Red

    $UserName = $Upn -split "@"

    $AuditLogPath = ".\" + $UserName[0] + "AuditLog" + (Get-Date).ToString('MM-dd-yyyy') + ".csv"

    $StartDate = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy') 

    $EndDate = (Get-Date).ToString('MM/dd/yyyy')

    $Results = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $Upn

    $Results | Export-Csv -Path $AuditLogPath

    Write-Host "Log of this command can be found here: $AuditLogPath. You can also review the activity below." -ForegroundColor Green

    $Results | Format-Table    

} # End Function Get-AuditLog




# BELOW THIS LINE EXECUTES THE ABOVE CREATED FUNCTIONS---------------------------------------------------------------------------

    Reset-Password $Upn

    Enable-MailboxAuditing $Upn

    Remove-MailboxDelegates $Upn

    Disable-MailforwardingRulesToExternalDomains $Upn

    Remove-MailboxForwarding $Upn

    Get-AuditLog $Upn

    Stop-Transcript

} # End Else
