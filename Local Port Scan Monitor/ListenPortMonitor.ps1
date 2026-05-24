#Requires -Version 3.0
#Requires -Modules NetTCPIP
Function Watch-OpenPorts {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$True,
                Position=0)]
            [PSCredential]$Credential,
    
            [Parameter(
                Mandatory=$True,
                Position=1)]
            [String]$SmtpServer,
    
            [Parameter(
                Mandatory=$True,
                Position=2)]
            [String]$FromEmail,
    
            [Parameter(
                Mandatory=$True,
                Position=3)]
            [String]$ToEmail,
    
            [Parameter(
                Mandatory=$False,
                Position=4)]
            [String]$OutputPath = "C:\Users\Public\Documents"
        )  # End Param

    BEGIN {

        Clear-Variable -Name DomainInfo,PDC,PreviouslyOpenPorts,CurrentlyOpenPorts,NewOpenPorts,EstablishedConnections,NewConnections,DnsResults -ErrorAction SilentlyContinue
        $PortHistoryPath = Join-Path -Path $OutputPath -ChildPath "OpenPortHistory.csv"
        $ConnectionHistoryPath = Join-Path -Path $OutputPath -ChildPath "ConnectionHistory.csv"
        $ConnectionDNSHistoryPath = Join-Path -Path $OutputPath -ChildPath "ConnectionDNSHistory.csv"
        If (!(Test-Path -Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -ErrorAction SilentlyContinue | Out-Null
        }  # End If

        Try {
            $DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $PDC = $DomainInfo.PdcRoleOwner.Name
        } Catch {
            Write-Verbose -Message "[*] Could Not Determine PDC. DNS Lookups Will Use Default Resolver."
            $PDC = $Null
        }  # End Try Catch

    } PROCESS {

        Write-Verbose -Message "[*] Getting Currently Listening Ports"
        $CurrentlyOpenPorts = Get-NetTCPConnection -State Listen | Select-Object -Property LocalAddress,LocalPort,State,OwningProcess | Sort-Object -Property LocalPort -Unique
        If (!(Test-Path -Path $PortHistoryPath)) {

            Write-Verbose -Message "[*] Creating Initial Open Port Baseline"
            $CurrentlyOpenPorts | Export-Csv -Path $PortHistoryPath -NoTypeInformation

        } Else {

            Write-Verbose -Message "[*] Comparing Current Open Ports To Previous Baseline"
            $PreviouslyOpenPorts = Import-Csv -Path $PortHistoryPath
            $NewOpenPorts = Compare-Object `
                -ReferenceObject $PreviouslyOpenPorts `
                -DifferenceObject $CurrentlyOpenPorts `
                -Property LocalPort |
                Where-Object -FilterScript {
                    $_.SideIndicator -eq "=>"
                } |
                Select-Object -ExpandProperty LocalPort -Unique

            If ($NewOpenPorts) {

                Write-Output -InputObject "[!] New Listening Port Detected On $env:COMPUTERNAME"
                $Body = "If you have received this email it is because a new listening port was opened on $env:COMPUTERNAME. If this was due to a user configuration or new application you may disregard. Otherwise verify that a bind shell connection has not been established to this device.`n`nNew Ports:`n$($NewOpenPorts -join "`n")"
                Try {

                    Send-MailMessage `
                        -From $FromEmail `
                        -To $ToEmail `
                        -Body $Body `
                        -Subject "AD Event: New Listen Port Opened On $env:COMPUTERNAME" `
                        -SmtpServer $SmtpServer `
                        -Priority Normal `
                        -Credential $Credential `
                        -UseSSL `
                        -Port 587 `
                        -ErrorAction Stop
                    Write-Verbose -Message "[*] Email Sent"

                } Catch {
                    Write-Output -InputObject "[x] Failed Sending Open Port Alert Email"
                    Write-Output -InputObject $_
                }  # End Try Catch
                $CurrentlyOpenPorts | Export-Csv -Path $PortHistoryPath -NoTypeInformation

            } Else {
                Write-Verbose -Message "[*] No New Listening Ports Found"
            }  # End If Else

        }  # End If Else

        Write-Verbose -Message "[*] Logging Established Connections"
        $EstablishedConnections = Get-NetTCPConnection -State Established | Sort-Object -Property RemoteAddress -Unique | Select-Object -Property LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,OwningProcess,CreationTime
        If (!(Test-Path -Path $ConnectionHistoryPath)) {

            Write-Verbose -Message "[*] Creating Initial Connection History"
            $EstablishedConnections | Export-Csv -Path $ConnectionHistoryPath -Delimiter ',' -NoTypeInformation
            $DnsResults = ForEach ($Established in $EstablishedConnections.RemoteAddress) {

                If ($PDC) {
                    Resolve-DnsName -Name $Established -Server $PDC -ErrorAction SilentlyContinue | Select-Object -Property Name,Type,NameHost
                } Else {
                    Resolve-DnsName -Name $Established -ErrorAction SilentlyContinue | Select-Object -Property Name,Type,NameHost
                }  # End If Else

            }  # End ForEach

            $DnsResults | Export-Csv -Path $ConnectionDNSHistoryPath -Delimiter ',' -NoTypeInformation

        } Else {

            Write-Verbose -Message "[*] Comparing Established Connections To Previous History"
            $NewConnections = Compare-Object -ReferenceObject (Import-Csv -Path $ConnectionHistoryPath) -DifferenceObject $EstablishedConnections -Property RemoteAddress | Where-Object -FilterScript {
                    $_.SideIndicator -eq "=>"
            } | Select-Object -ExpandProperty RemoteAddress -Unique

            ForEach ($NewConnection in $NewConnections) {

                $EstablishedConnections | Where-Object -Property RemoteAddress -Like $NewConnection | Export-Csv -Path $ConnectionHistoryPath -Append -NoTypeInformation
                If ($PDC) {
                    Resolve-DnsName -Name $NewConnection -Server $PDC -ErrorAction SilentlyContinue | Select-Object -Property Name,Type,NameHost | Export-Csv -Path $ConnectionDNSHistoryPath -Append -NoTypeInformation -Delimiter ','
                } Else {
                    Resolve-DnsName -Name $NewConnection -ErrorAction SilentlyContinue | Select-Object -Property Name,Type,NameHost | Export-Csv -Path $ConnectionDNSHistoryPath -Append -NoTypeInformation -Delimiter ','
                }  # End If Else

            }  # End ForEach

        }  # End If Else

    } END {
    
    }  # End B P E

}  # End Function Watch-OpenPorts
