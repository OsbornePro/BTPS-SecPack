<#
.SYNOPSIS
This cmdlet is used to discover new devices that have joined the network based on Client ID History of the DHCP Servers.


.PARAMETER DhcpServers
This parameter defines an array of DHCP servers in the environment

.PARAMETER ComparePath
This parameter defines the location of the csv file containing MAC history information. If the file does not exist it will be created.

.PARAMETER MacVendorps1
This parameter defines where the locations of the Get-MacVendor.ps1 file is


.DESCRIPTION
Find-NewDevices was made to discover new devices to have joined the network based on Client ID histroy of the DHCP Servers. This was made for System Administrators and does not take any input


.NOTES
Author: Robert H. Osborne
Contact: rosborne@osbornepro.com
Alias: tobor


.EXAMPLE
Find-NewDevices -DhcpServers 'DHCP1','10.10.10.10','DHCP3.domain.com' -ComparePath 'C:\DhcpHistory.csv' -MacVendorps1 .\Get-MacVendor.ps1
# This example discvoers never before seen devies on the 3 different DHCP servers and sends an email if any are discovered.


.LINK
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
None

#>
Function Find-NewDevices {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="Define the DHCP server or servers for the environment.")]  # End Parameter
            [String[]]$DhcpServers,

            [Parameter(
                Mandatory=$True,
                Position=1,
                HelpMessage="Define the full path and file name to the csv file that will contain the MAC address history records.")]  # End Parameter
            [String]$ComparePath,

            [Parameter(
                Mandatory=$True,
                Position=2,
                HelpMessage="Define the full path and file name of the file containing the Get-MacVendor.ps1 file and cmdlet")]  # End Parameter
            [String]$MacVendorps1

        )  # End param

    Import-Module -Name DhcpServer

    ForEach ($DhcpServer in $DhcpServers) {

        Clear-Variable TableInfo,MailBody,PreContent,PostContent,NoteLine -ErrorAction SilentlyContinue

        Write-Verbose "[*] Obtaining Scope Values"
        $Scopes = @()
        $Scopes = (Get-DhcpServerv4Scope -ComputerName $DhcpServer | Select-Object -ExpandProperty "ScopeID").IPAddressToString

        Write-Verbose '[*] Finding Active Address Leases'
        Try {

            Write-Verbose "[*] Building list of all clients in all DHCP scopes on $DhcpServer"

            $CurrentDhcpList = @()
            $CurrentDhcpList = ForEach ($Scope in $Scopes) {

                Get-DHCPServerv4Lease -ComputerName $DhcpServer -ScopeID $Scope -AllLeases -ErrorAction SilentlyContinue | Where-Object { $_.AddressState -like '*Active' }

            } # End Foreach

            If (Test-Path -Path "$ComparePath") {

                Write-Verbose "[*] List of known MAC Addresses has been found."

            } # End If
            Else {

                Write-Verbose "[*] Initial Build of file containing MAC Address history is being created at $ComparePath"
                $CurrentDhcpList | Select-Object -Property ClientID,IPAddress,ScopeID,Hostname,AddressState,LeaseExpiryTime | Export-Csv -Path "$ComparePath" -NoTypeInformation

            } # End Else

            $HistoryDhcpList = Import-Csv -Path "$ComparePath" -Header ClientID

            If ($CurrentDhcpList) {

                Write-Verbose "[*] Comparing Client ID History with Current Leases"

                $NewMacAddresses = @()
                $NewMacAddresses = (Compare-Object -ReferenceObject $HistoryDhcpList -DifferenceObject $CurrentDhcpList -Property ClientId | Where-Object {$_.SideIndicator -like "=>"}) | Select-Object -Property ClientId -ExcludeProperty SideIndicator -ExpandProperty ClientId -Unique

            } # End If
            Else {

                Write-Output "[!] There were not any DHCP clients retrieved from $DhcpServer"
                Break

            } # End Else

            If ($NewMacAddresses) {

                Write-Verbose "[*] Obtaining client lease information for newly found devices. "

                $AllInfo = @()
                $AllInfo = ForEach ($Scope in $Scopes) {
                    # Uncomment and modify the where-object part of this pipe if you wish to exclude certain hostnames for whatever reason
                    (Get-DhcpServerv4Lease -ComputerName $DhcpServer -ClientId $NewMacAddresses -ScopeId $Scope -ErrorAction SilentlyContinue) # | Where-Object -Property HostName -NotLike "DESKTOP*"

                } # End Foreach


                Write-Verbose "[*] Updating Client ID History"
                If ($AllInfo) {

                    Write-Verbose "[*] Appending list of known MAC Addresses"
                    $AllInfo | Select-Object -Property IPAddress,ScopeID,ClientID,Hostname,AddressState,LeaseExpiryTime | Export-Csv -Path $ComparePath -Append # Updates the HistoryDhcpList File

                }  # End If
                Else {

                    Write-Verbose "[*] No accompanying information obtained for that MAC Address"

                }  # End Else

                Write-Verbose "[*] Getting Vendor Information from MAC Addresses of newly discovered devies"
                Import-module -Function ."$MacVendorps1" -Force

                $VendorList = @()
                $VendorList = Get-MACVendor -MacAddress $NewMacAddresses

                If (!($VendorList)) {

                    Write-Output "[*] No matching vendor could be determined from the current MAC vendor list. If you believe this to be an error check the Get-MacVendor.ps1 file at $MacVendorps1"

                } # End If

            }  # End If
            Else {

                Write-Output "[*] No new devices were discovered on $DhcpServer."

            }  # End Else

        }  # End Try
        Catch {

            Write-Output "[x] Error encountered with $DhcpServer"
            $Error[0]

        }  # End Catch
        Finally {

            Import-Module -Function ."$MacVendorps1" -Force

            $Table = @()
            $Table = ForEach ($Vendor in $AllInfo) {

                $VendorAssignment = Get-MacVendor -MACAddress $Vendor.ClientId

                New-Object -TypeName PSObject -Property @{DhcpServer = $DhcpServer
                                                          HostName = $Vendor.HostName
                                                          Scope = $Vendor.ScopeId
                                                          IPAddress = $Vendor.IPAddress
                                                          ClientId = $Vendor.ClientId
                                                          Vendor = $VendorAssignment.Vendor

                 } # End Property

             } # End ForEach
             
        Write-Verbose 'Generating Information for email...'
        $TableInfo = @()
        $TableInfo = $Table | Select-Object -Property Vendor,HostName,IPAddress,ClientId
        
        If ($TableInfo) {

            $ArrayTable = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'
            $TableInfo | ForEach-Object {

            $Section = @{
                activityTitle = "New Device Joined Network"
                activitySubtitle = "$($_.HostName)"
                activityText  = "New Device $($_.HostName) received IP Address $($_.IPAddress)"
                activityImage = ""
	            facts		  = @(
                      @{
                          name = "Hostname: "
                          value = $_.HostName
                       }
                      @{
                          name = "Scope ID: "
                          value = $_.ScopeID
                       },
                      @{
                          name = "IP Address: "
                          value = $_.IPAddress
                       },
                      @{
                          name = "MAC Address: "
                          value = $_.ClientId
                       },
                      @{
                          name = "Vendor: "
                          value = $_.Vendor
                       },
                      @{
                          name = "Message"
                          value = "New device connected to network"
                      }
                )  # End Facts

	        }  # End Section

	        $ArrayTable.Add($Section)

        }  # End ForEach-Object

        $Body = ConvertTo-Json -Depth 8 @{
            title = "New Device Joined Network"
	        text  = "There are $($ArrayTable.Count) new devices to join the network"
	        sections = $ArrayTable
            potentialAction =   @(
                            @{
                                '@context'  = 'http://schema.org'
                                '@type' = 'ViewAction'
                                name = 'Elasticsearch for Correlation Events'
                                target = @("SIEM TOOL LINK")
                            }
                        )  # End Potential Actions
            }  # End Body


            $WebhookUrl = 'WEBHOOK_URL_REPLACE'

            # Post the JSON Array Object to the Webhook Connector URI
            Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Body -ContentType 'application/json'
            Write-Verbose 'Notification sent.'

           } # End If
           Else { 

                Write-Verbose "No new devices found."

           } # End Else

        } # End Finally
  
    } # End Foreach DHCP Server

} # End Function
