<#
.SYNOPSIS
Finds insecure LDAP binds by extracting Event ID 2889 from the Directory Service event log.


.DESCRIPTION
Find-InsecureLDAPBinds searches the Directory Service event log for Event ID 2889.

These events identify unsigned or simple LDAP binds made to a Domain Controller. This can help identify applications, systems, or users performing weak LDAP authentication.

LDAP Interface Events diagnostic logging must be enabled for Event ID 2889 to be generated.


.PARAMETER ComputerName
Defines the Domain Controller to query.

The default value is localhost.


.PARAMETER Hours
Defines the number of hours back to search the Directory Service event log.

The default value is 24.


.PARAMETER Credential
Defines the PSCredential object used for SMTP authentication.


.PARAMETER SmtpServer
Defines the SMTP server used to send the alert email.


.PARAMETER FromEmail
Defines the sender email address.


.PARAMETER ToEmail
Defines the recipient email address.


.INPUTS
System.String.


.OUTPUTS
System.Management.Automation.PSCustomObject.


.EXAMPLE
Find-InsecureLDAPBinds `
    -ComputerName localhost `
    -Hours 24 `
    -Credential (Get-Credential) `
    -SmtpServer mail.domain.com `
    -FromEmail alert@domain.com `
    -ToEmail sysadmin@domain.com `
    -Verbose

This example searches the local Domain Controller for insecure LDAP bind events from the last 24 hours and sends an HTML email alert if any are discovered.
#>

Function Find-InsecureLDAPBinds {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$False,
            Position=0,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$True,
            HelpMessage="Enter FQDN, hostname, or IP Address of domain controller")]
        [String]$ComputerName = "localhost",

        [Parameter(
            Mandatory=$False,
            Position=1)]
        [Int]$Hours = 24,

        [Parameter(
            Mandatory=$True,
            Position=2)]
        [PSCredential]$Credential,

        [Parameter(
            Mandatory=$True,
            Position=3)]
        [String]$SmtpServer,

        [Parameter(
            Mandatory=$True,
            Position=4)]
        [String]$FromEmail,

        [Parameter(
            Mandatory=$True,
            Position=5)]
        [String]$ToEmail
    )  # End param

    BEGIN {

        Clear-Variable -Name Events,InsecureLDAPBinds,Final,MailBody,TableInfo,PreContent,PostContent,NoteLine -ErrorAction SilentlyContinue
        Try {

            If ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -ErrorAction Stop).'16 LDAP Interface Events' -eq 0) {

                Write-Verbose -Message "[*] Insecure LDAP Binds Are Not Currently Being Logged. Enabling Logging Of Insecure LDAP Binds."
                New-ItemProperty `
                    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" `
                    -Name '16 LDAP Interface Events' `
                    -Value 2 `
                    -Force `
                    -ErrorAction Stop | Out-Null

            }  # End If

        } Catch {

            Write-Output -InputObject "[x] Failed Checking Or Enabling LDAP Interface Events Diagnostics"
            Write-Output -InputObject $_

        }  # End Try Catch
        $InsecureLDAPBinds = @()

    } PROCESS {

        Try {

            Write-Verbose -Message "[*] Searching Event Log For ID 2889"
            $Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
                    LogName   = 'Directory Service'
                    Id        = 2889
                    StartTime = (Get-Date).AddHours(-$Hours)
                } -ErrorAction Stop

        } Catch {

            Write-Output -InputObject "[x] Failed Searching Directory Service Event Log On $ComputerName"
            Write-Output -InputObject $_
            Return

        }  # End Try Catch

        ForEach ($Event in $Events) {

            Try {

                $EventXML = [Xml]$Event.ToXml()
                $Client = ($EventXML.Event.EventData.Data[0])
                $IPAddress = $Client.SubString(0,$Client.LastIndexOf(":")) # Accomodates for IPV6 Addresses
                $Port = $Client.SubString($Client.LastIndexOf(":")+1) # Accomodates for IPV6 Addresses
                $User = $EventXML.Event.EventData.Data[1]
                Switch ($EventXML.Event.EventData.Data[2]) {

                    0 {$BindType = "Unsigned"}
                    1 {$BindType = "Simple"}
                    Default {$BindType = "Unknown"}

                }  # End Switch

                $InsecureLDAPBinds += [PSCustomObject]@{
                    IPAddress = $IPAddress
                    Port      = $Port
                    User      = $User
                    BindType  = $BindType
                }  # End PSCustomObject

            } Catch {

                Write-Output -InputObject "[x] Failed Parsing Event ID 2889"
                Write-Output -InputObject $_

            }  # End Try Catch

        }  # End ForEach

        Write-Verbose -Message "[*] Adding Discovered Values If Any To Results"
        $Final = $InsecureLDAPBinds | ForEach-Object -Process {
            Try {

                $Hostname = Resolve-DnsName `
                    -Name $_.IPAddress `
                    -Server $env:COMPUTERNAME `
                    -ErrorAction Stop |
                    Select-Object -ExpandProperty Name -First 1

            } Catch {
                $Hostname = "Unable To Resolve"
            }  # End Try Catch
            [PSCustomObject]@{
                Hostname  = $Hostname
                IPAddress = $_.IPAddress
                Port      = $_.Port
                User      = $_.User
                BindType  = $_.BindType
                Message   = "Insecure LDAP Bind Performed"
            }  # End PSCustomObject
        }  # End ForEach-Object

        If ($Final) {

$Css = @"
<style>
table {
    font-family: verdana,arial,sans-serif;
    font-size:11px;
    color:#333333;
    border-width:1px;
    border-color:#666666;
    border-collapse:collapse;
}
th {
    border-width:1px;
    padding:8px;
    border-style:solid;
    border-color:#666666;
    background-color:#dedede;
}
td {
    border-width:1px;
    padding:8px;
    border-style:solid;
    border-color:#666666;
    background-color:#ffffff;
}
</style>
"@ # End CSS

            Write-Verbose -Message "[*] Building Email Body"
            $PreContent = "<Title>NOTIFICATION: Insecure LDAP Binds Performed</Title>"
            $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
            $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
            $MailBody = $Final |
                ConvertTo-Html `
                    -Head $Css `
                    -PostContent $PostContent `
                    -PreContent $PreContent `
                    -Body "<br>The below table contains information on LDAP connections over the last $Hours hours that used unsigned or simple binds.<br><br><hr><br><br>" |
                Out-String

            Try {

                Send-MailMessage `
                    -From $FromEmail `
                    -To $ToEmail `
                    -Subject "AD Event: Insecure LDAP Binds Performed" `
                    -BodyAsHtml `
                    -Body $MailBody `
                    -SmtpServer $SmtpServer `
                    -Credential $Credential `
                    -UseSSL `
                    -Port 587 `
                    -ErrorAction Stop
                Write-Verbose -Message "[*] Email Sent"

            } Catch {
                Write-Output -InputObject "[x] Failed Sending Email"
                Write-Output -InputObject $_
            }  # End Try Catch

        } Else {
            Write-Verbose -Message "[*] No Insecure LDAP Bind Events Were Found"
        }  # End If Else

    } END {

    }  # End END

}  # End Function Find-InsecureLDAPBinds
