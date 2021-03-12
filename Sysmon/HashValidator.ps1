# This script is for extracting the IMPHASH from Sysmon logs in order to compare the hash to a whitelist of known Windows Processes. This will then log any processes that do not appear on the whitelist
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# IMPORTANT : GET A VIRUS TOTAL API KEY FROM https://www.virustotal.com/gui/join-us and place it in the value below
$VirusTotalApiKey = ''

$LogName = "Hash Validations"
$LogfileExists = Get-WinEvent -ListLog "Hash Validations" -ErrorAction SilentlyContinue
If (!($LogfileExists))
{

    New-EventLog -LogName $LogName -Source $LogName
    Limit-EventLog -LogName $LogName -OverflowAction OverWriteAsNeeded -MaximumSize 64KB

}  # End If


# Below 2 functions I stole from https://community.cisco.com/t5/security-blogs/powershell-using-virustotal-api-to-find-unknown-file-reputation/ba-p/3410001
Function Search-VirusTotal {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                HelpMessage="`n[H] Enter a hash value that Virus Total is capable of comparing `n[E] EXAMPLE: F586835082F632DC8D9404D83BC16316")]  # End Parameter
            [String]$Hash
        )  # End param

    $Body = @{ resource = $Hash; apikey = $VTApiKey }
    $VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $Body
    $AVScanFound = @()

    If ($VTReport.positives -gt 0)
    {

        ForEach($Scan in ($VTReport.scans | Get-Member -Type NoteProperty))
        {

            If ($Scan.Definition -Match "detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})")
            {
                If ($Matches.Detected -Eq "True")
                {

                    $AVScanFound += "{0}({1}) - {2}" -f $Scan.Name, $Matches.Version, $Matches.Result

                }  # End If

            }  # End If

        }  # End ForEach

    }  # End If

    New-Object –TypeName PSObject -Property ([ordered]@{
        MD5 = $VTReport.MD5
        SHA1 = $VTReport.SHA1
        SHA256 = $VTReport.SHA256
        VTLink = $VTReport.permalink
        VTReport = "$($VTReport.positives)/$($VTReport.total)"
        VTMessage = $VTReport.verbose_msg
        Engines = $AVScanFound
    })  # End New-Object

} # Function Search-VirusTotal


Function Get-VirusTotalReport {
    Param (
        [Parameter(
            Mandatory=$True,
            Position=0)]
        [String]$VTApiKey,

        [Parameter(
            Mandatory=$True,
            Position=1,
            ValueFromPipeline=$True,
            ParameterSetName='byHash')]  # End Parameter
        [String[]] $Hash
    )  # End param

    $Hash | ForEach-Object { Search-VirusTotal -Hash $_ }  # End ForEach-Object

}  # End Function Get-VirusTotalReport


$Event = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1; StartTime=(Get-Date).AddHours(-1.2)} | Select-Object -ExpandProperty Message | Out-String
$Hashes = $Event | ForEach-Object { $_ -Split '\s{2}|:' | Where-Object { $_ -Match ',IMPHASH=' } }
$ImpHashes = $Hashes | ForEach-Object { $_ -Replace "(?i)(?:.*?=)", "" } | Select-Object -Unique
$Md5Hashes = $Hashes | ForEach-Object { $_.Trim() -Replace "[^,]*$", "" -Replace 'MD5=','' -Replace ',','' } | Select-Object -Unique

ForEach ($H in $Md5Hashes)
{

    $Result = Get-VirusTotalReport -VTApiKey $VirusTotalApiKey -Hash $H
    If ($Result.VTReport[0] -gt 0)
    {

        $Event = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1; StartTime=(Get-Date).AddHours(-1.2)}
        $Hashes = ($Event.Message | Out-String) | ForEach-Object { $_ -Split '\s{2}|:' | Where-Object { $_ -Match " MD5=$H" } }
        $Obj = New-Object -TypeName PSObject -Properties @{MD5=$Result.MD5; SHA1=$Result.SHA1; $SHA256=$Result.SHA256; VTInfoLink=$Result.VTLink; }

    }  # End If
    # The Free Virus Total API allows only 1 call every 15 seconds which is why we have Start-Sleep here
    Start-Sleep -Seconds 15

}  # End ForEach
