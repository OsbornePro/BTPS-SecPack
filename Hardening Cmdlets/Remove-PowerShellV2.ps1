<#
.SYNOPSIS
This cmdlet is used to remove PowerShell version 2 from a device if it is installed. PowerShell v2 is able to be used in a PowerShell downgrade attack which bypasses modern PowerShell defenses.


.DESCRIPTION
This cmdlet checks whether or not PowerShell version 2 is installed and then removes it if it is.


.PARAMETER ComputerName
This parameter can be used to define the local or remote device(s) in which to disable PowerShell version 2


.EXAMPLE
Remove-PowerShellV2
# This example removes PowerShell version 2 if it is installed on the local machine

.EXAMPLE
Remove-PowerShellV2 -ComputerName DC01,Desktop20
# This example removes PowerShell version 2 from the remote devices DC01 and Desktop20


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Remove-PowerShellV2 {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]  # End Parameter
            [Alias('cn','Computer')]
            [ValidateNotNullOrEmpty()]
            [String[]]$ComputerName
        )  # End param

Switch ($PSBoundParameters.Keys) {
    'ComputerName' {

        ForEach ($C in $ComputerName)
        {

            $SessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
            # This option to an attempt to accomdate any environment and should not be needed if WinRM over HTTPS is configured correctly

            Invoke-Command -HideComputerName "$C.$env:USERDNSDOMAIN" -UseSSL -SessionOption $SessionOption -ScriptBlock {

                Write-Verbose "[*] Checking whether or not PowerShell version 2 is installed on the $env:COMPUTERNAME"
                $State = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State

                Switch ($State)
                {

                    "Enabled" {

                        Write-Output "[!] $env:COMPUTERNAME is vulnerable to a PowerShell downgrade attack"
                        Write-Output "[*] Removing PowerShell Version 2 to remediate PowerShell Downgrade Attack vulnerability"

                        Try
                        {

                            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -Remove

                        }  # End Try
                        Catch
                        {

                            Write-Output "[*] SAFE: PowerShell version 2 is not installed on $env:COMPUTERNAME"

                        }  # End Catch

                    }  # End Enabled Switch

                    "Disabled" {

                        Write-Output "[*] SAFE: PowerShell version 2 is not installed on $env:COMPUTERNAME"

                    }  # End Disabled Switch

                }  # End Switch

            }  # End Invoke-Command

        }  # End ForEach

    }  # End ComputerName Switch

    Default {

        Write-Verbose "[*] Checking whether or not PowerShell version 2 is installed on the host"
        $State = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State

        Switch ($State)
        {

            "Enabled" {

                Write-Output "[!] $env:COMPUTERNAME is vulnerable to a PowerShell downgrade attack"
                Write-Output "[*] Removing PowerShell Version 2 to remediate PowerShell Downgrade Attack vulnerability"

                Try
                {

                    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -Remove

                }  # End Try
                Catch
                {

                    Write-Output "[*] SAFE: PowerShell version 2 is not installed on $env:COMPUTERNAME"

                }  # End Catch

            }  # End Enabled Switch

            "Disabled" {

                Write-Output "[*] SAFE: PowerShell version 2 is not installed on $env:COMPUTERNAME"

            }  # End Disabled Switch

        }  # End Switch

    }  # End Default Switch

}  # End Switch

}  # End Function Remove-PowerShellV2
