<#
.SYNOPSIS
This cmdlet is used to disable NetBIOS on a local or remote device(s). This prevents the ability of an attacker to capture password hashes with tools such as Responder


.DESCRIPTION
This cmdlet modifies the registry values HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip NetbiosOptions to the value 2 which disables NetBIOS
SetTcpopNetbios option:
0 - Use NetBIOS setting from the DHCP server
1 - Enable NetBIOS over TCP/IP
2 - Disable NetBIOS over TCP/IP


.PARAMETER ComputerName
This parameter defines the remote device you wish to disable NetBIOS on

.PARAMETER UseSSL
This parameter indicates you wish to use WinRM over HTTPS when executing commands on the remote devices

.PARAMETER Undo
This switch parameter indicates you wish to re-enable NetBIOS on a local or remote machine you accidently or incorrectly disabled NetBIOS on

.PARAMETER UseDHCPNetBIOSSetting
This switch parameter indicates you wish to use the DHCP servers settings to define whether NetBIOS is enabled or not

.PARAMETER EnableLMHOSTS
This switch parameter can be used to enable LMHOST usage instead of disabling it


.EXAMPLE
Disable-NetBIOS
# This example disables NetBIOS on all interfaces on the local machine

.EXAMPLE
Disable-NetBIOS -Undo
# This example re-enables NetBIOS on all interfaces on the local machine

.EXAMPLE
Disable-NetBIOS -UseDHCPNetBIOSSetting
# This example uses DHCP settings to determine the NetBIOS settings on all interfaces on the local machine

.EXAMPLE
Disable-NetBIOS -ComputerName 'DC01','DC02.domain.com'
# This example disables NetBIOS on all interfaces on DC01 and DC02.domain.com using WinRM

.EXAMPLE
Disable-NetBIOS -ComputerName 'DC01','DC02.domain.com' -UseSSL -Undo
# This example re-enables NetBIOS on all interfaces on DC01 and DC02.domain.com using WinRM over HTTPS


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com
Also as a side note the two commands below can be used to disable LMHOSTS and NetBIOS
$CIMInstance = Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration
$CIMInstance | Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2}
Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }


.INPUTS
None


.OUTPUTS
None


.LINK
https://roberthosborne.com
https://osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
#>
Function Disable-NetBIOSandLMHOSTS {
    [CmdletBinding(DefaultParameterSetName='Local')]
        param(
            [Parameter(
                ParameterSetName='Remote',
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define a remote computer(s) you wish to disable NetBIOS on. `n[E] EXAMPLE: Desktop01.domain.com, DC01, DHCP.domain.com")]  # End Parameter
            [String[]]$ComputerName,

            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$UseSSL,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$Undo,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$UseDHCPNetBIOSSetting,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$EnableLMHOSTS
        )  # End param

    If ((Get-CimInstance -ClassName Win32_ComputerSystem).PartofDomain)
    {
    
        $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        
    }  # End If

    Switch ($PSCmdlet.ParameterSetName)
    {

        'Remote' {

            $Bool = $False
            If ($UseSSL.IsPresent)
            {

                $Bool = $True

            }  # End If
            
            $Lmhost = $False
            If ($EnableLMHOSTS.IsPresent)
            {
            
                $Lmhost = $True
                
            }  # End If

            ForEach ($C in $ComputerName) 
            {
                
                Write-Verbose "Changing NetBIOS settings on $C"

                If ($C -notlike "*.$Domain")
                {

                    $C = "$C.$Domain"

                }  # End If

                Invoke-Command -ArgumentList $Undo,$UseDHCPNetBIOSSetting,$Lmhost -HideComputerName $C -UseSSL:$Bool -ScriptBlock {
                    
                    $Undo = $Args[0]
                    $UseDHCPNetBIOSSetting = $Args[1]
                    $Lmhost = $Args[2]
                    $Value = 2

                    If ($Lmhost -eq $True)
                    {
                    
                        Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }
                    
                    }  # End If
                    ElseIf ($Lmhost -eq $False)
                    {
                    
                        Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $True; WINSEnableLMHostsLookup = $True }
                    
                    }  # End ElseIf
                    
                    
                    If ($Undo.IsPresent)
                    {

                        Write-Verbose "NetBIOS will be ENABLED"
                        $Value = 1

                    }  # End If
                    ElseIf ($UseDHCPNetBIOSSetting.IsPresent)
                    {

                        Write-Verbose "NetBIOS Setting will be determined by the DHCP server reservation"
                        $Value = 0

                    }  # End ElseIf

                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions -Value $Value
                    $CurrentSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions | Select-Object -Property NetbiosOptions -Unique
                
                    If ($CurrentSetting.NetbiosOptions -eq 2)
                    {

                        Write-Output "[*] NetBIOS has been Disabled on $env:COMPUTERNAME"

                    }  # End If
                    Else
                    {

                        Write-Output "[!] Not all interfaces have NetBIOS disabled on $env:COMPUTERNAME"
                        $CurrentSetting

                    }  # End Else
                    
                    $LMSetting = (Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration).WINSEnableLMHostsLookup | Select-Object -Unique
                    If ($LMSetting -eq $False)
                    {

                        Write-Output "[*] The use of the LMHOSTS file has been disabled on $env:COMPUTERNAME"

                    }  # End If
                    Else
                    {

                        Write-Output "[!] The use of the LMHOSTS file has been enabled on $env:COMPUTERNAME"

                    }  # End Else
            
                }  # End Invoke-Command
            
            }  # End ForEach

        }  # End Switch Remote

        'Local' {

            If ($EnableLMHOSTS.IsPresent)
            {
                    
                Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $True; WINSEnableLMHostsLookup = $True }
                    
            }  # End If
            Else
            {
                    
                Invoke-CimMethod -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration -MethodName EnableWINS -Arguments @{ DNSEnabledForWINSResolution = $False; WINSEnableLMHostsLookup = $False }
                    
            }  # End ElseIf
                    
            $Value = 2
            If ($Undo.IsPresent)
            {

                Write-Verbose "NetBIOS will be ENABLED"
                $Value = 1

            }  # End If
            ElseIf ($UseDHCPNetBIOSSetting.IsPresent)
            {

                Write-Verbose "NetBIOS Setting will be determined by the DHCP server reservation"
                $Value = 0

            }  # End ElseIf


            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions -Value $Value
           
            
            $CurrentSetting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip*" -Name NetbiosOptions | Select-Object -Property NetbiosOptions -Unique
            If ($CurrentSetting.NetbiosOptions -eq 2)
            {

                Write-Output "[*] NetBIOS has been Disabled on $env:COMPUTERNAME"

            }  # End If
            Else
            {

                Write-Output "[!] Not all interfaces have NetBIOS disabled on $env:COMPUTERNAME"
                $CurrentSetting

            }  # End Else
            
            $LMSetting = (Get-CimInstance -Namespace root/CIMV2 -ClassName Win32_NetworkAdapterConfiguration).WINSEnableLMHostsLookup | Select-Object -Unique
            If ($LMSetting -eq $False)
            {
            
                Write-Output "[*] The use of the LMHOSTS file has been disabled on $env:COMPUTERNAME"
            
            }  # End If
            Else
            {

                Write-Output "[!] The use of the LMHOSTS file has been enabled on $env:COMPUTERNAME"

            }  # End Else

        }  # End Switch Local

    }  # End Switch

}  # End Function Disable-NetBIOSandLMHOSTS
