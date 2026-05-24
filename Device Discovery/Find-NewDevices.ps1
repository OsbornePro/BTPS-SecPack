#Requires -Version 3.0
#Requires -Modules DhcpServer
<#
.SYNOPSIS
This cmdlet is used to discover newly connected devices on the network based on DHCP Client ID history.


.DESCRIPTION
Find-NewDevices was created to identify devices that have not previously appeared in DHCP lease history across one or more DHCP servers.

The cmdlet retrieves all active DHCP leases from every scope on the specified DHCP servers and compares the current Client IDs against a historical csv file containing previously discovered MAC addresses.

If newly discovered devices are identified:
    • Vendor information is resolved using the embedded Get-MACVendor helper function
    • A formatted HTML email report is generated
    • The newly discovered MAC addresses are appended to the historical comparison file

This cmdlet is intended for System Administrators performing asset discovery, rogue device monitoring, or DHCP lease auditing.

.PARAMETER DhcpServers
Defines an array of DHCP servers to query for active leases.

.PARAMETER ComparePath
Defines the full path to the csv file used to store historical MAC address information.
If the file does not exist, it will automatically be created during the first execution.

.PARAMETER Credential
Defines the PSCredential object used for SMTP authentication when sending email notifications.

.PARAMETER SmtpServer
Defines the SMTP server used for sending email notifications.

.PARAMETER FromEmail
Defines the sender email address used for the notification email.

.PARAMETER ToEmail
Defines the recipient email address used for the notification email.


.EXAMPLE
PS> Find-NewDevices `
    -DhcpServers "DHCP01","DHCP02","10.10.10.10" `
    -ComparePath "C:\Logs\DhcpHistory.csv" `
    -Credential (Get-Credential) `
    -SmtpServer "smtp.domain.com" `
    -FromEmail "dhcp-alerts@domain.com" `
    -ToEmail "sysadmin@domain.com" `
    -Verbose
# This example retrieves all active DHCP leases from the specified DHCP servers, compares them against the historical MAC address csv file, identifies newly discovered devices, resolves vendor information, updates the history file, and sends an HTML email report containing the newly discovered devices.


.INPUTS
None.
You cannot pipe objects to this cmdlet.


.OUTPUTS
None.
This cmdlet generates verbose output, writes informational messages to the console, updates a csv history file, and optionally sends HTML email notifications.


.NOTES
Author: Robert H. Osborne
Contact: rosborne@osbornepro.com

Requirements:
    • PowerShell 3.0+
    • DhcpServer PowerShell Module
    • MAC vendor csv file located at:
        C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv

The MAC vendor csv file must contain the following headers:
    • Assignment
    • Organization Name


.LINK
https://osbornepro.com
https://github.com/OsbornePro
https://www.powershellgallery.com/profiles/tobor
#>
Function Get-MACVendor {
    [CmdletBinding()]
    param(
        [Parameter(
            Position=0,
            Mandatory=$True,
            HelpMessage='MAC-Address or the first 6 digits of it')]
        [ValidateScript({
            If ($_ -match "^(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})|([0-9A-Fa-f]{2}){6})|([0-9A-Fa-f]{2}[:-]){2}([0-9A-Fa-f]{2})|([0-9A-Fa-f]{2}){3}$") {
                Return $true
            } Else {
                Throw "Enter a valid MAC-Address (like 00:00:00:00:00:00 or 00-00-00-00-00-00)!"
            }  # End Else
        })]  # End ValidateScript
        [String[]]$MACAddress
    )  # End param

    BEGIN {

        # MAC-Vendor list path
        ##################################################################################################################
        $CSV_MACVendorList_Path = "C:\Users\Public\Documents\PSGetHelp\MAC.Vendor.List.csv"

        If ([System.IO.File]::Exists($CSV_MACVendorList_Path)) {
            $MAC_VendorList = Import-Csv -Path $CSV_MACVendorList_Path | Select-Object -Property "Assignment", "Organization Name"
            #### The above values may change depending on your csv file. Just replace Assignment and Organization Name with whatever the headers are in your csv
        } Else {
            Throw [System.IO.FileNotFoundException] "No CSV-File to assign vendor with MAC-Address found!"
        }  # End Else

    } PROCESS {

        ForEach ($MACAddress2 in $MACAddress) {

            $Vendor = [String]::Empty
            # Split it, so we can search the vendor (XX-XX-XX-XX-XX-XX to XX-XX-XX)
            $MAC_VendorSearch = $MACAddress2.Replace("-","").Replace(":","").Substring(0,6)
            ForEach ($ListEntry in $MAC_VendorList) {

                If ($ListEntry.Assignment -eq $MAC_VendorSearch) {

                    $Vendor = $ListEntry."Organization Name"
                    [PSCustomObject] @{
                        ClientId = $MACAddress2
                        Vendor   = $Vendor
                    }  # End CustomObject

                }  # End If

            }  # End ForEach

        }  # End ForEach

    } END {

    }  # End B P E

}  # End Function Get-MacVendor

Function Find-NewDevices {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$True,
            Position=0,
            HelpMessage="Define the DHCP server or servers for the environment.")]
        [String[]]$DhcpServers,

        [Parameter(
            Mandatory=$True,
            Position=1,
            HelpMessage="Define the full path and file name to the csv file that will contain the MAC address history records.")]
        [String]$ComparePath,

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
    )  # End Param

    Import-Module -Name DhcpServer -ErrorAction Stop
    ForEach ($DhcpServer in $DhcpServers) {

        Clear-Variable -Name TableInfo,MailBody,PreContent,PostContent,NoteLine,AllInfo,Table,VendorList,NewMacAddresses -ErrorAction SilentlyContinue
        Write-Verbose "[*] Obtaining Scope Values"
        Try {
            $Scopes = Get-DhcpServerv4Scope -ComputerName $DhcpServer -ErrorAction Stop | Select-Object -ExpandProperty ScopeID
        } Catch {
            Write-Output -InputObject "[x] Failed Obtaining Scopes From $DhcpServer"
            Write-Output -InputObject $_
            Continue
        }  # End Try Catch

        Write-Verbose -Message "[*] Finding Active Address Leases"
        Try {

            Write-Verbose -Message "[*] Building list of all clients in all DHCP scopes on $DhcpServer"
            $CurrentDhcpList = ForEach ($Scope in $Scopes) {
                Get-DhcpServerv4Lease `
                    -ComputerName $DhcpServer `
                    -ScopeID $Scope `
                    -AllLeases `
                    -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.AddressState -like '*Active' }  # End Where-Object

            }  # End ForEach

            If (!($CurrentDhcpList)) {
                Write-Output -InputObject "[!] No DHCP Clients Retrieved From $DhcpServer"
                Continue
            }  # End If

            If (!(Test-Path $ComparePath)) {
                Write-Verbose -Message "[*] Initial Build of MAC Address History File"
                $CurrentDhcpList | Select-Object -Property ClientID | Export-Csv -Path $ComparePath -NoTypeInformation
            }  # End If

            Write-Verbose -Message "[*] Importing MAC Address History"
            $HistoryDhcpList = Import-Csv -Path $ComparePath

            Write-Verbose -Message "[*] Comparing Client ID History With Current Leases"
            $NewMacAddresses = Compare-Object -ReferenceObject $HistoryDhcpList.ClientID -DifferenceObject $CurrentDhcpList.ClientID | Where-Object -FilterScript {
                $_.SideIndicator -eq "=>"
            } | Select-Object -ExpandProperty InputObject -Unique

            If ($NewMacAddresses) {

                Write-Verbose -Message "[*] New Devices Discovered"
                $AllInfo = ForEach ($Scope in $Scopes) {
                    Get-DhcpServerv4Lease `
                        -ComputerName $DhcpServer `
                        -ScopeId $Scope `
                        -ClientId $NewMacAddresses `
                        -ErrorAction SilentlyContinue

                }  # End ForEach

                If ($AllInfo) {
                    Write-Verbose -Message "[*] Updating Client ID History"
                    $AllInfo | Select-Object -Property ClientID | Export-Csv -Path $ComparePath -Append -NoTypeInformation
                }  # End If

                Write-Verbose -Message "[*] Getting Vendor Information"
                $VendorList = Get-MACVendor -MacAddress $NewMacAddresses
                If (!($VendorList)) {
                    Write-Output -InputObject "[!] No Matching Vendor Information Found"
                }  # End If

            } Else {
                Write-Output -InputObject "[*] No New Devices Were Discovered On $DhcpServer"
                Continue
            }  # End If Else

        } Catch {

            Write-Output -InputObject "[x] Error Encountered With $DhcpServer"
            Write-Output -InputObject $_
            Continue
        }  # End Try Catch

        $Table = ForEach ($Vendor in $AllInfo) {
            $VendorAssignment = Get-MacVendor -MacAddress $Vendor.ClientId
            [PSCustomObject]@{
                DhcpServer = $DhcpServer
                HostName  = $Vendor.HostName
                Scope     = $Vendor.ScopeId
                IPAddress = $Vendor.IPAddress
                ClientId  = $Vendor.ClientId
                Vendor    = $VendorAssignment.Vendor
            }  # End PSCustomObject

        }  # End ForEach

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
"@

        Write-Verbose -Message "[*] Generating Information For Email"
        $TableInfo = $Table | Select-Object Vendor,HostName,IPAddress,ClientId
        $PreContent = "<Title>Newest Devices To Have Joined The Network</Title>"
        $NoteLine = "$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
        $MailBody = $TableInfo | ConvertTo-Html `
                        -Head $Css `
                        -PostContent $PostContent `
                        -PreContent $PreContent `
                        -Body "This is a list of the newest devices to have joined the network." | Out-String

        If ($Table) {
            Try {
                Send-MailMessage `
                    -From $FromEmail `
                    -To $ToEmail `
                    -Subject "AD Event: New Device Check $DhcpServer" `
                    -BodyAsHtml `
                    -Body $MailBody `
                    -SmtpServer $SmtpServer `
                    -UseSSL `
                    -Port 587 `
                    -Credential $Credential
                Write-Verbose -Message "[*] Email Sent"
            } Catch {
                Write-Output -InputObject "[x] Failed Sending Email For $DhcpServer"
                Write-Output -InputObject $_
            }  # End Try Catch
        } Else {
            Write-Verbose -Message "[*] No New Devices Found"
        }  # End If Else

    }  # End ForEach

}  # End Function Find-NewDevices
