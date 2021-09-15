<#
.SYNOPSIS
Exports a CSV from the specified domain controller containing all Unsgined and Clear-text LDAP binds made to the DC by extracting Event 2889 from the "Directory Services" event log. This extract can be used to identifiy applications and hosts performing weak and insecure LDAP binds. The events extracted by the script are only generated when LDAP diagnostics are enabled as per below.


.PARAMETER ComputerName
Specifies one or more computers. The default is the local computer. Type the NETBIOS name, an IP address, or a fully qualified domain name of a remote computer. To specify the local computer, type the computer name, a dot (.), or localhost. This parameter does not rely on Windows PowerShell remoting. You can use the ComputerName parameter even if your computer is not configured to run remote commands.

.PARAMETER Hours
This parameter defines the number of hours to check for insecure LDAP Binds in the Event Log


.DESCRIPTION
Execute the script against the DomainController which has had the diagnostic logging enabled. By default, the script will return the past 24 hours worth of events. You can increase or decrease this value as desired


.LINK
https://technet.microsoft.com/en-us/library/dd941829(v=ws.10).aspx
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
System.String You can pipe computer names to this cmdlet..
In Windows PowerShell 2.0, the ComputerName parameter takes input from the pipeline only by property name. In Windows PowerShell 3.0, the ComputerName parameter takes input from the pipeline by value.


.OUTPUTS
System.String The CSV list is sent to the file designated in the Path parameter.
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
            [Int]$Hours = 24)

    If ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics").'16 LDAP Interface Events' -eq 0) {

        Write-Verbose "Insecure LDAP Binds are not currently being logged. Enabling logging of insecure LDAP Binds."
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" -Name '16 LDAP Interface Events' -Value 2 -Force

    }  # End If
    $InsecureLDAPBinds = @()

    Write-Verbose "[*] Searching Event Log for ID 2889"
    $Events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{Logname='Directory Service';Id=2889; StartTime=(Get-Date).AddHours("-$Hours")}

    ForEach ($Event in $Events) {

        $EventXML = [xml]$Event.ToXml()

        $Client = ($EventXML.Event.EventData.Data[0])
        $IPAddress = $Client.SubString(0,$Client.LastIndexOf(":")) #Accomodates for IPV6 Addresses
        $Port = $Client.SubString($Client.LastIndexOf(":")+1) #Accomodates for IPV6 Addresses
        $User = $EventXML.Event.EventData.Data[1]

        Switch ($EventXML.Event.EventData.Data[2]) {

            0 {$BindType = "Unsigned"}
            1 {$BindType = "Simple"}

        }  # End Switch

        $Row = "" | Select-Object -Property "IPAddress","Port","User","BindType"
        $Row.IPAddress = $IPAddress
        $Row.Port = $Port
        $Row.User = $User
        $Row.BindType = $BindType

        $InsecureLDAPBinds += $Row

    }  # End ForEach

    Write-Verbose "[*] Adding discovered values if any to CSV file"
    $InsecureLDAPBinds

}  # End Function Find-InsecureLDAPBinds

$Results = Find-InsecureLDAPBinds -ComputerName localhost -Hours 24 -Verbose
$Final = $Results | ForEach-Object {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property "Hostname","IPAddress","Port","User","BindType","Message"
            $Obj.Hostname = $(Resolve-DnsName -Name $_.IPAddress -Server $env:COMPUTERNAME | Select-Object -ExpandProperty Name -First 1 | Out-String)
            $Obj.IPAddress = $_.IPAddress
            $Obj.Port = $_.Port
            $Obj.User = $_.User
            $Obj.BindType = $_.BindType
            $Obj.Message = "Insceure LDAP Bind Performed"

            $Obj

}  # End ForEach-Object
    
If ($Final) {

    $Css = @"
<style>
table {
    font-family: verdana,arial,sans-serif;
        font-size:11px;
        color:#333333;
        border-width: 1px;
        border-color: #666666;
        border-collapse: collapse;
}
th {
        border-width: 1px;
        padding: 8px;
        border-style: solid;
        border-color: #666666;
        background-color: #dedede;
}
td {
        border-width: 1px;
        padding: 8px;
        border-style: solid;
        border-color: #666666;
        background-color: #ffffff;
}
</style>
"@ # End CSS
    $PreContent = "<Title>NOTIFICATION: Insecure LDAP Binds Performed</Title>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
    $MailBody = $Final | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on connections to LDAP over the last 24 hours that did not use SSL.<br><br><hr><br><br>" | Out-String

   Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: Insecure LDAP Binds Performed" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -Credential $Credential -UseSSL -Port 587

}  # End If
