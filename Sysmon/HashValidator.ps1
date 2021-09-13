# This script is for extracting the IMPHASH and MD5 Hash from Sysmon logs in order to compare the hash to a whitelist of known Windows Processes. This will then log any processes that do not appear on the whitelist
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# IMPORTANT : GET A VIRUS TOTAL API KEY FROM https://www.virustotal.com/gui/join-us and place it in the value below
$VirusTotalApiKey = ''

$WhitelistPath = "$env:USERPROFILE\Downloads\BTPS-SecPack-Master\Sysmon\Whitelist.csv"
# To help you add more to your whitelist I have included the commands I used to build this one below
# Create a collection of files to get hashes of and move the results into a text file in case you have large amounts of files to add
# Get-ChildItem -Path 'C:\Program Files\','C:\Program Files (x86)','C:\Windows','C:\Sysinternals\' -Include "*.exe","*.dll" -Recurse -ErrorAction SilentlyContinue -File -Force | Select-Object -ExpandProperty "FullName" | Out-File -FilePath .\Whitelist.txt -Append
#
# This command grabs the file name and MD5 hash and places the values into a CSV file
# Get-Content .\Whitelist.txt | ForEach-Object { $Md5Hash = Get-FileHash -Path $_ -Algorithm MD5 | Select-Object -ExpandProperty Hash; $FileName = $_.Split('\')[-1]; $Object = New-Object -TypeName PSObject -Property @{FileName=$FileName; MD5=$Md5Hash}; $Object | Select-Object -Property FileName,MD5 | Export-Csv -NoTypeInformation -Path .\Whitelist.csv -Append }
If (!(Test-Path -Path $WhitelistPath)) {

    Throw "Please define the location of Whitelist.csv on line 5 of this script. A starting template has been included in the BTPS SecPack Sysmon directory"

}  # End If


If ($Null -eq $VirusTotalApiKey) {

    Throw "GET A VIRUS TOTAL API KEY FROM https://www.virustotal.com/gui/join-us and place it in this script as the $VirusTotalApiKey variable on line 15"

}  # End If


$FinalResults = @()
$LogName = "Hash Validations"
$LogfileExists = Get-WinEvent -ListLog "Hash Validations" -ErrorAction SilentlyContinue
If (!($LogfileExists)) {

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

    $Body = @{resource = $Hash; apikey = $VTApiKey}
    $VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $Body
    $AVScanFound = @()

    If ($VTReport.positives -gt 0) {

        ForEach($Scan in ($VTReport.scans | Get-Member -Type NoteProperty)) {

            If ($Scan.Definition -Match "detected=(?<detected>.*?); version=(?<version>.*?); result=(?<result>.*?); update=(?<update>.*?})") {

                If ($Matches.Detected -Eq "True") {

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
            Position=0,
            HelpMessage="GET A VIRUS TOTAL API KEY FROM https://www.virustotal.com/gui/join-us and place it in the value below")]  # End Parameter
        [String]$VTApiKey,

        [Parameter(
            Mandatory=$True,
            Position=1,
            ValueFromPipeline=$True)]  # End Parameter
        [String[]] $Hash
    )  # End param

    $Hash | ForEach-Object { Search-VirusTotal -Hash $_ }  # End ForEach-Object

}  # End Function Get-VirusTotalReport


$Whitelist = Import-Csv -Path $WhitelistPath -Delimeter "," | Select-Object -Property "MD5"
$Events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1; StartTime=(Get-Date).AddHours(-1.2)}

$Obj = $Events | ForEach-Object {

            $Hash = $_ | Select-Object -ExpandProperty Message | Out-String | ForEach-Object { $_ -Split '\s{2}|:' | Where-Object { $_ -Match ',IMPHASH=' } | Select-Object -Unique }
            $ImpHash = $Hash | ForEach-Object { $_ -Replace "(?i)(?:.*?=)", "" }
            $Md5Hash = $Hash | ForEach-Object { $_.Trim() -Replace "[^,]*$", "" -Replace 'MD5=','' -Replace ',','' }

            If ($Whitelist.MD5 -NotContains $Md5Hash) {

                $VTResult = Get-VirusTotalReport -VTApiKey $VirusTotalApiKey -Hash $Md5Hash
                # The Free Virus Total API allows only 1 call every 15 seconds which is why we have Start-Sleep here
                Start-Sleep -Seconds 15

                If ($VTResult.VTReport[0] -gt 0) {

                    $Obj = New-Object -TypeName PSObject | Select-Object -Property VTInfoLink, MD5, SHA1, SHA256, IMPHASH, ProcessPath, MachineName, EventCreation, MoreInfo
                        $Obj.VTInfoLink = $VTResult.VTLink
                        $Obj.MD5 = $Md5Hash
                        $Obj.SHA1 = $VTResult.SHA1
                        $Obj.SHA256 = $VTResult.SHA256
                        $Obj.IMPHASH = $ImpHash
                        $Obj.ProcessPath = $_.Properties[4].Value
                        $Obj.MachineName = $_.MachineName
                        $Obj.EventCreation = $_.TimeCreated
                        $Obj.MoreInfo = $_.Message

                    $FinalResults += $Obj

                    Write-EventLog -LogName $LogName -Source $LogName -EntryType Information -EventId 4444 -Message ($Obj | Out-String)

                    $Obj

                }  # End If

            }  # End If

}  # End ForEach-Object

# If you want email alerts set up for this you can uncomment the below lines
#If ($FinalResults)
#{

#    Send-MailMessage -From FromEmail -To ToEmail -Subject "ALERT: Process not on Whitelist Has Been Run" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -UseSSL -Port 587  -Credential $Credential

#} # End If
