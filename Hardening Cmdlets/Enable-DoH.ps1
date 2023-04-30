#Requires -Version 3.0
#Requires -RunAsAdministrator
Function Enable-DoH {
<#
.SYNOPSIS
This cmdlet modifies the registry to enable DNS over HTTPS for all apps in Windows 10 versions 19628+


.PARAMETER Restart
If this parameter is defined the executioner will be prompted to restart the computer to fully apply the change.


.EXAMPLE
PS> Enable-DoH
# This example enables DNS over HTPS on a windows machine.

.EXAMPLE .
PS> Enable-DoH -Restart
# This example enables DNS over HTTPS on a Windows machines and then restarts the computer after the runner confirms

.EXAMPLE
PS> Enable-DoH -Undo -Restart
# This example disable DNS over HTTPS on a Windows machine and restarts the computer after the runner confirms


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://osbornepro.com/f/dns-protections-and-applications
https://osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
None


.OUTPUTS
System.String
#>
    [OutputType([System.String])]
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [Switch]$Restart,

            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [Switch]$Undo
        )  # End param

PROCESS {

    If (((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\").EnableAutoDOH) -eq 2) {

        $Result = "DNS over HTTPS is already configured on $env:COMPUTERNAME"

    }  # End If


    If ($Undo.IsPresent) {


        Write-Verbose -Message "[v] Removing registry item that enables the use of DNS over HTTPS for all Windows Applications"
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDOH -Force
        $Result = "DNS over HTTPS is being disabled. Device will require a restart for change to finish taking effect"

    } Else {

        Write-Verbose -Message "[v] Enabling DNS over HTTPS for all Windows applications"
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDOH -PropertyType DWORD -Value 2 -Force
        $Result = "DNS over HTTPS is being enabled. Device will require a restart for change to finish taking effect"

    }  # End Else

} END {

    $Result
    If ($Restart.IsPresent) {

        Write-Verbose -Message "[v] Prompting to verify you wish to resart $env:COMPUTERNAME now"
        Restart-Computer -Confirm

    }  # End If

}  # End Function Enable-DoH
