# GET YOUR API KEY FROM https://user.whoisxmlapi.com/

<#
.SYNOPSIS
This cmdlet is used to extract all of the unique IPv4 addresses out from each line of a log file


.DESCRIPTION
Use a ForEach type statement to extract unique IPv4 address out from each line of a log file


.PARAMETER String
Defines the string of text that the regular expression of an IPv4 address should be tested for

.PARAMETER Path
Defines the path to a file you want to grab unique IP addresses out out


.EXAMPLE
ForEach ($Line in (Get-Content -Path C:\Temp\firewall.log)) { Get-ValidIPAddressFromString -String $Line }
# This example parses the text file firewall.log and lists any IPv4 Addresses found on each line

.EXAMPLE
Get-ValidIpAddressFromString -Path C:\Windows\System32\LogFiles\Firewall\domainfw.log


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
System.String


.OUTPUTS
System.String

#>
Function Get-ValidIPAddressFromString {
    [CmdletBinding(DefaultParameterSetName="Line")]
        param(
            [Parameter(
                ParameterSetName="Line",
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="`n[H] Enter a string to extract the IPv4 address out of `n[E] EXAMPLE: Log File 8/6/2020 10.10.10.10. DENY TCP")]  # End Parameter
            [String]$String,
        
            [Parameter(
                ParameterSetName="File",
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$Path)  # End param
       

    $Obj = @()
    $Regex=‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’

    Switch ($PsCmdlet.ParameterSetName)
    {
        'File' {

            $FileContents = Get-Content -Path $Path -Tail 5000
            ForEach ($Line in $FileContents)
            {

                If (($Line -Match $Regex) -and ($Obj -notcontains $Matches.Address))
                {
    
                        $Obj += $Matches.Address
        
                }  # End If



            }  # End ForEach
            
            Return $Obj
        
        }  # End File Switch

        'Line' {
        
            If ($String -Match $Regex)
            {
                
                $Obj = $Matches.Address

            }  # End If

            $Obj

        }  # End Default Switch

    }  # End Switch 

}  # End Function Get-ValidIPAddressFromString


Function Get-WhoIsLookupInfo {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$True)]  # End Parameter
            [String]$APIKey,
    
            [Parameter(
                Mandatory=$True)]  # End Parameter
            [String[]]$DomainName)  # End param


    $Responses = @()

    $DomainName | ForEach-Object {

        $RequestUri = "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=$APIKey&domainName=$_&outputFormat=JSON"

        $Responses += Invoke-RestMethod -Method GET -Uri $RequestUri

    }  # End ForEach-Object


    Function Get-ValidDate {
        [CmdletBinding()]
            param(
                [Parameter(
                    Position=0)]  # End Parameter
                [String]$Value, 
            
                [Parameter(
                    Position=1)]  # End Parameter
                [String]$Date)  # End param
             
        $DefaultDate = $Value."$($Date)Date"
        $NormalizedDate = $Value.RegistryData."$($Date)DateNormalized"

        If (![String]::IsNullOrEmpty($DefaultDate)) 
        {

            Get-Date -Date $DefaultDate

        }  # End If
    
        Return [DateTime]::ParseExact($NormalizedDate, "yyyy-MM-dd HH:mm:ss UTC", $Null)
     
    }  # End Function Get-ValidDate
 
    $Properties = "DomainName", "DomainNameExt",
    @{N = "CreatedDate"; E = { Get-ValidDate $_ "Created" } },
    @{N = "UpdatedDate"; E = { Get-ValidDate $_ "Updated" } },
    @{N = "ExpiresDate"; E = { Get-ValidDate $_ "Expires" } },
    "RegistrarName",
    "ContactEmail",
    "EstimatedDomainAge",
    @{N = "Contact"; E = { ($_.Registrant | Select-Object -Property * -ExcludeProperty RawText ).PSObject.Properties.Value -Join ", " } }

    $WhoIsInfo = $Responses.WhoisRecord | Select-Object -Property $Properties
    $WhoIsInfo | Format-Table -AutoSize

}  # End Function Get-WhoIsLookupInfo


$TmpEventFile = "C:\Windows\Temp\SysmonEvents.txt"
$IPFile = 'C:\Program Files (x86)\NirSoft\IPNetInfo\IPs.txt'


# Get-WinEvent -FilterHashTable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=3; StartTime=(Get-Date).AddHours(-1)} | Select-Object -ExpandProperty Message | Out-File -FilePath $TmpEventFile

$IPList = Get-ValidIPAddressFromString -Path C:\Users\Public\Documents\ConnectionHistory.csv # $TmpEventFile
ForEach ($IP in $IPList)
{

    $DomainName = Resolve-DnsName -Name $IP -Server 1.1.1.1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost -ErrorAction SilentlyContinue

    If ($DomainName)
    {
        
        $Results += Get-WhoIsLookupInfo -APIKey <Your API Key Here> -DomainName $DomainName -ErrorAction SilentlyContinue

    }  # End If


}  # End ForEach  
