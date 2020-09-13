<#
.SYNOPSIS
This cmdlet modifies the registry to enable DNS over HTTPS for all apps in Windows 10 versions 19628+


.PARAMETER Restart
If this parameter is defined the executioner will be prompted to restart the computer to fully apply the change.


.EXAMPLE
Enable-DoH
# This example enables DNS over HTPS on a windows machine.

.EXAMPLE .
Enable-DoH -Restart
# This example enables DNS over HTTPS on a Windows machines and then restarts the computer after the runner confirms

.EXAMPLE
Enable-DoH -Undo -Restart
# This example disable DNS over HTTPS on a Windows machine and restarts the computer after the runner confirms


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
None


.OUTPUTS
None

#>
Function Enable-DoH {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$Restart,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$Undo
        )  # End param

    If (((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\").EnableAutoDOH) -eq 2)
    {

        Write-Output "[*] DNS over HTTPS is already configured on $env:COMPUTERNAME"

    }  # End If


    If ($PSBoundParameters.Keys -eq 'Undo')
    {


        Write-Verbose "[*] Removing registry item that enables the use of DNS over HTTPS for all Windows Applications"
        Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDOH -Force

    }  #  End If
    Else
    {

        Write-Verbose "[*] Enabling DNS over HTTPS for all Windows applications"
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDOH -PropertyType DWORD -Value 2 -Force

    }  # End Else


    If ($PSBoundParameters.Keys -eq 'Restart')
    {

        Restart-Computer -Confirm

    }  # End If

}  # End Function Enable-DoH
