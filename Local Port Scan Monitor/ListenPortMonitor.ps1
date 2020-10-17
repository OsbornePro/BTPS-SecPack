###########################################################################################
#                                                                                         #
# This shell is for monitoring ports and alerting IT when a new port is opened            #
#                                                                                         #
# Author: Robert Osborne                                                                  #
#                                                                                         #
# Contact: rosborne@osbornepro.com                                                        #
#                                                                                         #
# Last Updated 9/8/2020                                                                  #
#                                                                                         #
###########################################################################################
$DomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $DomainInfo.PdcRoleOwner.Name

# Monitor Bind Shells--------------------------------------------------------------------------
$PreviouslyOpenPorts = "34"
$CurrentlyOpenPorts = Get-NetTCPConnection -State Listen | Group-Object -Property LocalPort -NoElement 

Write-Verbose "Comparing current open port count to previously open port count"
If ($PreviouslyOpenPorts -lt $CurrentlyOpenPorts.Count)
{

    $Body = "If you have received this email it is because a new port was opened $nev:COMPUTERNAME. If this was due to a user configuration or new application you may disregard. Otherwise verify that a Bind Shell connection has not been established to this device."
    Send-MailMessage -From FromEmail -To ToEmail -Body $Body -Subject "AD Event: New Listen Port Opened on $env:COMPUTERNAME" -SmtpServer UseSmtpServer -Priority Normal -Credential $Credential -UseSSL -Port 587

}  # End If


Write-Verbose "Logging established connections"

$EstablishedConnections = Get-NetTCPConnection -State Established | Sort-Object -Property RemoteAddress -Unique | Select-Object -Property LocalPort,RemoteAddress,RemotePort,State,AppliedSetting,OwningProcess,CreationTime
If (!(Test-Path -Path 'C:\Users\Public\Documents\ConnectionHistory.csv')) 
{

    $EstablishedConnections | Export-Csv -Path 'C:\Users\Public\Documents\ConnectionHistory.csv' -Delimiter ',' -NoTypeInformation
      
    $DnsResults = ForEach ($Established in $EstablishedConnections.RemoteAddress) 
    {       
    
        Resolve-DnsName -Name $Established -Server $PDC -ErrorAction SilentlyContinue | Select-Object -Property Name,Type,NameHost

    } # End ForEach

    $DnsResults | Export-Csv -Path 'C:\Users\Public\Documents\ConnectionDNSHistory.csv' -Delimiter ',' -Append -NoTypeInformation

}# End If
Else 
{

    $NewConnections = Compare-Object -ReferenceObject (Import-Csv 'C:\Users\Public\Documents\ConnectionHistory.csv') -DifferenceObject $EstablishedConnections -Property RemoteAddress | Where-Object { $_.SideIndicator -like '=>'} | Select-Object -ExpandProperty RemoteAddress 

    ForEach ($NewConnection in $NewConnections) 
    {
    
        $EstablishedConnections | Where-Object -Property RemoteAddress -like $NewConnection | Export-Csv -Path 'C:\Users\Public\Documents\ConnectionHistory.csv' -Append
        
        Resolve-DnsName -Name $NewConnection -ErrorAction SilentlyContinue | Select-Object -Property Name,Type,NameHost | Export-Csv -Path 'C:\Users\Public\Documents\ConnectionDNSHistory.csv' -Append -NoTypeInformation -Delimiter ','

    } # End ForEach

} # End Else
