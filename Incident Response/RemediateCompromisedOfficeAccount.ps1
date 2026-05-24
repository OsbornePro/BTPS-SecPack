#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement,Microsoft.Graph.Users,Microsoft.Graph.Users.Actions
<#
.SYNOPSIS
Remediates a potentially compromised Microsoft 365 account.


.DESCRIPTION
This cmdlet performs Microsoft 365 account remediation actions for a potentially compromised user.

The following actions are performed:
    1.) Reset the user's password.
    2.) Revoke active user sign-in sessions.
    3.) Remove mailbox delegate permissions.
    4.) Disable inbox rules that forward, redirect, forward as attachment, or send SMS notifications.
    5.) Remove mailbox-level forwarding.
    6.) Enable mailbox auditing.
    7.) Export Unified Audit Log results for review.


.PARAMETER UserPrincipalName
Defines the affected user's UserPrincipalName.

.PARAMETER AdminUserPrincipalName
Defines the administrator account used to connect to Exchange Online.

.PARAMETER OutputPath
Defines where transcript and audit log files will be saved.

.PARAMETER AuditDays
Defines how many days back to search the Unified Audit Log.


.EXAMPLE
PS> Invoke-M365CompromisedAccountRemediation `
    -UserPrincipalName compromised.user@domain.com `
    -AdminUserPrincipalName admin@domain.com `
    -OutputPath "C:\Users\Public\Desktop" `
    -AuditDays 7 `
    -Verbose

#>
Function New-RandomPassword {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$False,
                Position=0
            )]  # End Parameter
            [Int]$Length = 20
        )  # End Param

    Add-Type -AssemblyName System.Web
    Return [System.Web.Security.Membership]::GeneratePassword($Length,4)

}  # End Function New-RandomPassword


Function Reset-M365UserPassword {
    [CmdletBinding(SupportsShouldProcess=$True)]
        param (
            [Parameter(
                Mandatory=$True,
                Position=0
        )]  # End Parameter
            [String]$UserPrincipalName
        )  # End Param

    $NewPassword = New-RandomPassword -Length 20
    $PasswordProfile = @{
        Password = $NewPassword
        ForceChangePasswordNextSignIn = $True
    }

    If ($PSCmdlet.ShouldProcess($UserPrincipalName,"Reset Password")) {

        Write-Verbose -Message "[*] Resetting Password For $UserPrincipalName"
        Update-MgUser -UserId $UserPrincipalName -PasswordProfile $PasswordProfile -ErrorAction Stop

        Write-Output -InputObject "[*] Password For $UserPrincipalName Was Reset"
        Write-Output -InputObject "[!] Temporary Password: $NewPassword"
        Write-Output -InputObject "[!] Store This Password Securely. The User Must Change It At Next Sign-In."

    }  # End If

}  # End Function Reset-M365UserPassword


Function Revoke-M365UserSessions {
    [CmdletBinding(
        SupportsShouldProcess=$True
    )]  # End CmdletBinding
    param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]  # End Parameter
        [String]$UserPrincipalName
    )  # End Param

    If ($PSCmdlet.ShouldProcess($UserPrincipalName,"Revoke Sign-In Sessions")) {
        Write-Verbose -Message "[*] Revoking Active Sign-In Sessions For $UserPrincipalName"
        Revoke-MgUserSignInSession -UserId $UserPrincipalName -ErrorAction Stop | Out-Null
        Write-Output -InputObject "[*] Active Sign-In Sessions Revoked For $UserPrincipalName"
    }  # End If

}  # End Function Revoke-M365UserSessions


Function Enable-M365MailboxAuditing {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]  # End Parameter
        [String]$UserPrincipalName
    )  # End Param

    If ($PSCmdlet.ShouldProcess($UserPrincipalName,"Enable Mailbox Auditing")) {

        Write-Verbose -Message "[*] Enabling Mailbox Auditing For $UserPrincipalName"

        Set-Mailbox `
            -Identity $UserPrincipalName `
            -AuditEnabled $True `
            -AuditLogAgeLimit 365 `
            -ErrorAction Stop

        Get-Mailbox -Identity $UserPrincipalName |
            Select-Object -Property Name,AuditEnabled,AuditLogAgeLimit

    }  # End If

}  # End Function Enable-M365MailboxAuditing


Function Remove-M365MailboxDelegates {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]  # End Parameter
        [String]$UserPrincipalName
    )  # End Param

    Write-Verbose -Message "[*] Finding Mailbox Delegate Permissions For $UserPrincipalName"
    $MailboxDelegates = Get-MailboxPermission -Identity $UserPrincipalName -ErrorAction Stop |
        Where-Object -FilterScript {
            ($_.IsInherited -ne $True) -and
            ($_.User -notlike "*SELF*")
        }  # End Where-Object

    If ($MailboxDelegates) {

        Write-Output -InputObject "[*] The Following Mailbox Delegates Were Found"
        $MailboxDelegates | Select-Object -Property User,AccessRights,Deny,IsInherited
        ForEach ($Delegate in $MailboxDelegates) {

            If ($PSCmdlet.ShouldProcess($UserPrincipalName,"Remove Mailbox Delegate $($Delegate.User)")) {
                Remove-MailboxPermission -Identity $UserPrincipalName -User $Delegate.User -AccessRights $Delegate.AccessRights -InheritanceType All -Confirm:$False -ErrorAction Stop
                Write-Output -InputObject "[*] Removed Delegate Permission For $($Delegate.User)"
            }  # End If

        }  # End ForEach

    } Else {
        Write-Verbose -Message "[*] No Mailbox Delegates Found For $UserPrincipalName"
    }  # End If Else

}  # End Function Remove-M365MailboxDelegates


Function Disable-M365MailboxForwardingRules {
    [CmdletBinding(
        SupportsShouldProcess=$True
    )]  # End CmdletBinding
        param (
            [Parameter(
                Mandatory=$True,
                Position=0
        )]  # End Parameter
            [String]$UserPrincipalName
        )  # End Param

    Write-Verbose -Message "[*] Finding Inbox Rules That Forward Or Redirect Mail For $UserPrincipalName"
    $InboxRules = Get-InboxRule -Mailbox $UserPrincipalName -ErrorAction Stop |
        Where-Object -FilterScript {
            ($_.Enabled -eq $True) -and
            (
                ($Null -ne $_.ForwardTo) -or
                ($Null -ne $_.ForwardAsAttachmentTo) -or
                ($Null -ne $_.RedirectTo) -or
                ($Null -ne $_.SendTextMessageNotificationTo)
            )
        }  # End Where-Object

    If ($InboxRules) {

        Write-Output -InputObject "[*] The Following Forwarding Or Redirect Rules Were Found"
        $InboxRules | Select-Object -Property Name,Description,Enabled,Priority,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,SendTextMessageNotificationTo
        ForEach ($Rule in $InboxRules) {

            If ($PSCmdlet.ShouldProcess($UserPrincipalName,"Disable Inbox Rule $($Rule.Name)")) {
                Disable-InboxRule -Mailbox $UserPrincipalName -Identity $Rule.Identity -Confirm:$False -ErrorAction Stop
                Write-Output -InputObject "[*] Disabled Inbox Rule $($Rule.Name)"
            }  # End If

        }  # End ForEach

    } Else {
        Write-Verbose -Message "[*] No Forwarding Or Redirect Inbox Rules Found For $UserPrincipalName"
    }  # End If Else

}  # End Function Disable-M365MailboxForwardingRules


Function Remove-M365MailboxForwarding {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]  # End Parameter
        [String]$UserPrincipalName
    )  # End Param

    Write-Verbose -Message "[*] Checking Mailbox Forwarding Configuration For $UserPrincipalName"
    $MailboxForwarding = Get-Mailbox -Identity $UserPrincipalName -ErrorAction Stop | Select-Object -Property Name,DeliverToMailboxAndForward,ForwardingAddress,ForwardingSmtpAddress
    $MailboxForwarding

    If (
        ($MailboxForwarding.DeliverToMailboxAndForward -eq $True) -or
        ($Null -ne $MailboxForwarding.ForwardingAddress) -or
        ($Null -ne $MailboxForwarding.ForwardingSmtpAddress)
    ) {

        If ($PSCmdlet.ShouldProcess($UserPrincipalName,"Remove Mailbox Forwarding")) {

            Set-Mailbox -Identity $UserPrincipalName -DeliverToMailboxAndForward $False -ForwardingAddress $Null -ForwardingSmtpAddress $Null -ErrorAction Stop
            Write-Output -InputObject "[*] Mailbox Forwarding Removed For $UserPrincipalName"

        }  # End If

    } Else {
        Write-Verbose -Message "[*] No Mailbox Forwarding Configuration Found For $UserPrincipalName"
    }  # End If Else

}  # End Function Remove-M365MailboxForwarding


Function Export-M365UserAuditLog {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]  # End Parameter
        [String]$UserPrincipalName,

        [Parameter(
            Mandatory=$True,
            Position=1
        )]  # End Parameter
        [String]$OutputPath,

        [Parameter(
            Mandatory=$False,
            Position=2
        )]  # End Parameter
        [Int]$AuditDays = 7
    )  # End Param

    $UserName = $UserPrincipalName -split "@"
    $AuditLogPath = Join-Path -Path $OutputPath -ChildPath "$($UserName[0])_AuditLog_$(Get-Date -Format 'MM-dd-yyyy').csv"
    $StartDate = (Get-Date).AddDays(-$AuditDays)
    $EndDate = Get-Date

    Write-Verbose -Message "[*] Searching Unified Audit Log For $UserPrincipalName"
    $Results = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $UserPrincipalName -ResultSize 5000 -ErrorAction Stop

    $Results | Export-Csv -Path $AuditLogPath -NoTypeInformation
    Write-Output -InputObject "[*] Audit Log Exported To $AuditLogPath"
    $Results

}  # End Function Export-M365UserAuditLog


Function Invoke-M365CompromisedAccountRemediation {
    [CmdletBinding(SupportsShouldProcess=$True)]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Enter The UserPrincipalName Of The Compromised User"
        )]  # End Parameter
        [ValidateNotNullOrEmpty()]
        [String]$UserPrincipalName,

        [Parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Enter The Admin UserPrincipalName Used To Connect To Exchange Online"
        )]  # End Parameter
        [ValidateNotNullOrEmpty()]
        [String]$AdminUserPrincipalName,

        [Parameter(
            Mandatory=$False,
            Position=2
        )]  # End Parameter
        [String]$OutputPath = "C:\Users\Public\Desktop",

        [Parameter(
            Mandatory=$False,
            Position=3
        )]  # End Parameter
        [Int]$AuditDays = 7
    )  # End Param

    BEGIN {

        Clear-Variable -Name TranscriptPath,SamAccountName -ErrorAction SilentlyContinue
        $SamAccountName = $UserPrincipalName -Split "@"
        $TranscriptPath = Join-Path -Path $OutputPath -ChildPath "$($SamAccountName[0])_RemediationTranscript_$(Get-Date -Format 'MM-dd-yyyy').txt"
        Try {

            If (!(Test-Path -Path $OutputPath)) {
                New-Item -ItemType Directory -Path $OutputPath -ErrorAction Stop | Out-Null
            }  # End If

        } Catch {

            Write-Output -InputObject "[x] Failed Creating Output Path $OutputPath"
            Write-Output -InputObject $_
            Return

        }  # End Try Catch

        Start-Transcript -Path $TranscriptPath -ErrorAction Stop
        Write-Output -InputObject "[*] $UserPrincipalName Will Have Remediation Actions Applied"
        Write-Output -InputObject "[*] Transcript Will Be Saved To $TranscriptPath"

        Try {

            Write-Verbose -Message "[*] Importing Microsoft Graph And Exchange Online Modules"
            Import-Module -Name Microsoft.Graph.Users,Microsoft.Graph.Users.Actions,ExchangeOnlineManagement -ErrorAction Stop

        } Catch {

            Write-Output -InputObject "[x] Failed Importing Required Modules"
            Write-Output -InputObject $_
            Stop-Transcript
            Return

        }  # End Try Catch

        Try {

            Write-Verbose -Message "[*] Connecting To Microsoft Graph"
            Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.AccessAsUser.All" -NoWelcome -ErrorAction Stop

        } Catch {

            Write-Output -InputObject "[x] Failed Connecting To Microsoft Graph"
            Write-Output -InputObject $_
            Stop-Transcript
            Return

        }  # End Try Catch

        Try {

            Write-Verbose -Message "[*] Connecting To Exchange Online"
            Connect-ExchangeOnline -UserPrincipalName $AdminUserPrincipalName -ShowBanner:$False -ErrorAction Stop

        } Catch {

            Write-Output -InputObject "[x] Failed Connecting To Exchange Online"
            Write-Output -InputObject $_
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Stop-Transcript
            Return

        }  # End Try Catch

    } PROCESS {

        Try {

            Reset-M365UserPassword -UserPrincipalName $UserPrincipalName
            Revoke-M365UserSessions -UserPrincipalName $UserPrincipalName
            Enable-M365MailboxAuditing -UserPrincipalName $UserPrincipalName
            Remove-M365MailboxDelegates -UserPrincipalName $UserPrincipalName
            Disable-M365MailboxForwardingRules -UserPrincipalName $UserPrincipalName
            Remove-M365MailboxForwarding -UserPrincipalName $UserPrincipalName
            Export-M365UserAuditLog -UserPrincipalName $UserPrincipalName -OutputPath $OutputPath -AuditDays $AuditDays

            Write-Output -InputObject "[*] $UserPrincipalName Account Remediation Completed"
            Write-Output -InputObject "[!] Review The Transcript And Audit Log To Confirm No Additional Action Is Required"

        } Catch {

            Write-Output -InputObject "[x] Error During Remediation For $UserPrincipalName"
            Write-Output -InputObject $_

        }  # End Try Catch

    } END {

        Try {

            Write-Verbose -Message "[*] Disconnecting From Exchange Online"
            Disconnect-ExchangeOnline -Confirm:$False -ErrorAction SilentlyContinue

        } Catch {

            Write-Output -InputObject "[x] Failed Disconnecting From Exchange Online"
            Write-Output -InputObject $_

        }  # End Try Catch

        Try {

            Write-Verbose -Message "[*] Disconnecting From Microsoft Graph"
            Disconnect-MgGraph -ErrorAction SilentlyContinue

        } Catch {

            Write-Output -InputObject "[x] Failed Disconnecting From Microsoft Graph"
            Write-Output -InputObject $_

        }  # End Try Catch
        Stop-Transcript

    }  # End B P E

}  # End Function Invoke-M365CompromisedAccountRemediation
