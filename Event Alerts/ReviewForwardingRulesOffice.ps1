<#
.SYNOPSIS
Checks Microsoft 365 mailboxes for inbox forwarding rules, mailbox delegate permissions, and SMTP forwarding.


.DESCRIPTION
This script connects to Exchange Online using the ExchangeOnlineManagement module.

It checks enabled user mailboxes for:
    - Inbox rules that forward, redirect, or forward as attachment
    - Mailbox delegate permissions
    - Mailbox-level SMTP forwarding

The results are exported to CSV files, emailed as attachments, and then cleaned up.


.PARAMETER UserPrincipalName
Defines the admin account used to connect to Exchange Online.

.PARAMETER OutputPath
Defines the folder where CSV reports will be temporarily saved.

.PARAMETER SmtpServer
Defines the SMTP server used to send the report email.

.PARAMETER FromEmail
Defines the sender email address.

.PARAMETER ToEmail
Defines the recipient email address.

.PARAMETER Credential
Defines the PSCredential object used for SMTP authentication.


.EXAMPLE
Find-Office365MailboxForwarding `
    -UserPrincipalName admin@domain.com `
    -OutputPath "C:\Users\Public\Office365" `
    -SmtpServer "smtp.domain.com" `
    -FromEmail "alerts@domain.com" `
    -ToEmail "sysadmin@domain.com" `
    -Credential (Get-Credential) `
    -Verbose
#>
Function Find-Office365MailboxForwarding {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0)]
        [String]$UserPrincipalName,

        [Parameter(
            Mandatory=$False,
            Position=1)]
        [String]$OutputPath = "C:\Users\Public\Office365",

        [Parameter(
            Mandatory=$True,
            Position=2)]
        [String]$SmtpServer,

        [Parameter(
            Mandatory=$True,
            Position=3)]
        [String]$FromEmail,

        [Parameter(
            Mandatory=$True,
            Position=4)]
        [String]$ToEmail,

        [Parameter(
            Mandatory=$True,
            Position=5)]
        [PSCredential]$Credential
    )  # End Param

    BEGIN {

        Clear-Variable -Name UserInboxRules,UserDelegates,SMTPForwarding,AllUsers,Attach -ErrorAction SilentlyContinue
        Write-Verbose -Message "[*] Importing Exchange Online Management Module"
        Try {
            Import-Module -Name ExchangeOnlineManagement -ErrorAction Stop
        } Catch {
            Write-Output -InputObject "[x] Failed Importing ExchangeOnlineManagement Module"
            Write-Output -InputObject $_
            Return
        }  # End Try Catch

        Write-Verbose -Message "[*] Connecting To Exchange Online"
        Try {
            Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -ShowBanner:$False -ErrorAction Stop
        } Catch {

            Write-Output -InputObject "[x] Failed Connecting To Exchange Online"
            Write-Output -InputObject $_
            Return

        }  # End Try Catch

        Try {

            If (!(Test-Path -Path $OutputPath)) {
                Write-Verbose -Message "[*] Creating Output Directory"
                New-Item -ItemType Directory -Path $OutputPath -ErrorAction Stop | Out-Null
            }  # End If

        } Catch {
            Write-Output -InputObject "[x] Failed Creating Output Directory"
            Write-Output -InputObject $_
            Disconnect-ExchangeOnline -Confirm:$False
            Return
        }  # End Try Catch

        $UserInboxRules = @()
        $UserDelegates = @()
        $SMTPForwarding = @()
        $AllUsers = @()

    } PROCESS {

        Try {

            Write-Verbose -Message "[*] Getting Enabled User Mailboxes"
            $AllUsers = Get-EXOMailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited -Properties UserPrincipalName,DisplayName,PrimarySmtpAddress | Where-Object -FilterScript {
                    $_.UserPrincipalName -notlike "*#EXT#*"
            }  # End Where-Object

        } Catch {

            Write-Output -InputObject "[x] Failed Getting Enabled User Mailboxes"
            Write-Output -InputObject $_
            Disconnect-ExchangeOnline -Confirm:$False
            Return

        }  # End Try Catch

        ForEach ($User in $AllUsers) {

            Write-Output -InputObject "Checking inbox rules and delegates for user: $($User.UserPrincipalName)"
            Try {

                $UserInboxRules += Get-InboxRule -Mailbox $User.UserPrincipalName -ErrorAction Stop | Where-Object -FilterScript {
                        ($Null -ne $_.ForwardTo) -or
                        ($Null -ne $_.ForwardAsAttachmentTo) -or
                        ($Null -ne $_.RedirectTo)
                } | Select-Object -Property @{Label='Mailbox'; Expression={$User.UserPrincipalName}},Name,Description,Enabled,Priority,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage

            } Catch {
                Write-Output -InputObject "[x] Failed Checking Inbox Rules For $($User.UserPrincipalName)"
                Write-Output -InputObject $_
            }  # End Try Catch

            Try {

                $UserDelegates += Get-MailboxPermission -Identity $User.UserPrincipalName -ErrorAction Stop |
                    Where-Object -FilterScript {
                        ($_.IsInherited -ne $True) -and
                        ($_.User -notlike "*SELF*")
                    } | Select-Object -Property @{Label='Mailbox';Expression={$User.UserPrincipalName}},User,AccessRights,Deny,IsInherited

            } Catch {

                Write-Output -InputObject "[x] Failed Checking Delegate Permissions For $($User.UserPrincipalName)"
                Write-Output -InputObject $_

            }  # End Try Catch

        }  # End ForEach

        Try {

            Write-Verbose -Message "[*] Checking Mailbox SMTP Forwarding"
            $SMTPForwarding = Get-Mailbox -ResultSize Unlimited | Where-Object -FilterScript {
                    ($Null -ne $_.ForwardingAddress) -or
                    ($Null -ne $_.ForwardingSMTPAddress)
                } | Select-Object -Property DisplayName,UserPrincipalName,ForwardingAddress,ForwardingSMTPAddress,DeliverToMailboxAndForward

        } Catch {

            Write-Output -InputObject "[x] Failed Checking Mailbox SMTP Forwarding"
            Write-Output -InputObject $_

        }  # End Try Catch

        $InboxRulePath = Join-Path -Path $OutputPath -ChildPath "MailForwardingRulesToExternalDomains.csv"
        $DelegatePath = Join-Path -Path $OutputPath -ChildPath "MailboxDelegatePermissions.csv"
        $SMTPForwardingPath = Join-Path -Path $OutputPath -ChildPath "MailboxSMTPForwarding.csv"

        Write-Verbose -Message "[*] Exporting Reports"

        $UserInboxRules | Export-Csv -Path $InboxRulePath -NoTypeInformation
        $UserDelegates | Export-Csv -Path $DelegatePath -NoTypeInformation
        $SMTPForwarding | Export-Csv -Path $SMTPForwardingPath -NoTypeInformation

        $Attach = $SMTPForwardingPath,$DelegatePath,$InboxRulePath

        Try {

            Write-Verbose -Message "[*] Sending Report Email"
            Send-MailMessage `
                -From $FromEmail `
                -To $ToEmail `
                -Attachments $Attach `
                -Priority Normal `
                -Subject 'Weekly Check Office365 Mailbox Forwarding Rules' `
                -Body 'Microsoft suggests reviewing this information once a week to ensure Outlook forwarding rules are not configured in a malicious or unusual manner.' `
                -SmtpServer $SmtpServer `
                -Credential $Credential `
                -UseSsl `
                -Port 587 `
                -ErrorAction Stop
            Write-Verbose -Message "[*] Email Sent"

        } Catch {

            Write-Output -InputObject "[x] Failed Sending Combined Report Email"
            Write-Output -InputObject $_
            ForEach ($Report in $Attach) {

                Try {

                    Write-Verbose -Message "[*] Sending Report Individually: $Report"
                    Send-MailMessage `
                        -From $FromEmail `
                        -To $ToEmail `
                        -Attachments $Report `
                        -Priority Normal `
                        -Subject 'Weekly Check Office365 Mailbox Forwarding Rules' `
                        -Body 'Microsoft suggests reviewing this information once a week to ensure Outlook forwarding rules are not configured in a malicious or unusual manner.' `
                        -SmtpServer $SmtpServer `
                        -Credential $Credential `
                        -UseSsl `
                        -Port 587 `
                        -ErrorAction Stop

                } Catch {

                    Write-Output -InputObject "[x] Failed Sending Report: $Report"
                    Write-Output -InputObject $_

                }  # End Try Catch

            }  # End ForEach

        }  # End Try Catch

    } END {

        Try {

            Write-Verbose -Message "[*] Cleaning Up CSV Reports"
            Get-ChildItem `
                -Path $OutputPath `
                -Include "*.csv" `
                -Recurse `
                -ErrorAction SilentlyContinue |
                Remove-Item -Force -ErrorAction SilentlyContinue

        } Catch {

            Write-Output -InputObject "[x] Failed Cleaning Up CSV Reports"
            Write-Output -InputObject $_

        }  # End Try Catch

        Try {

            Write-Verbose -Message "[*] Disconnecting From Exchange Online"
            Disconnect-ExchangeOnline -Confirm:$False

        } Catch {

            Write-Output -InputObject "[x] Failed Disconnecting From Exchange Online"
            Write-Output -InputObject $_

        }  # End Try Catch

    }  # End END

}  # End Function Find-Office365MailboxForwarding
