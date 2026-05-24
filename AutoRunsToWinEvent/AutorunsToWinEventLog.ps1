#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Executes the Sysinternals Autoruns CLI utility and writes Autoruns data to a custom Windows Event Log.


.DESCRIPTION
This script executes the Sysinternals Autoruns CLI utility, exports Autoruns data to CSV,
and writes each Autoruns entry into a custom Windows Event Log named "Autoruns".

The script also inventories select local privileged groups and writes group membership
information into the same Windows Event Log.


.PARAMETER AutorunsDirectory
Defines the directory used to store Autoruns related files.

.PARAMETER MaxLogSizeKB
Defines the maximum size in KB for the Autoruns Windows Event Log.


.INPUTS
None

.OUTPUTS
None


.NOTES
Requires:
- PowerShell 5.1
- Administrator privileges
- Sysinternals Autoruns CLI
#>
[CmdletBinding()]
param (
    [Parameter(
        Position = 0
    )]  # End Parameter
    [ValidateNotNullOrEmpty()]
    [String]$AutorunsDirectory = "$env:ProgramFiles\AutorunsToWinEventLog",

    [Parameter(
        Position = 1
    )]  # End Parameter
    [ValidateRange(1024, 16776960)]
    [Int64]$MaxLogSizeKB = 4194240
)  # End Param

If (!(Test-Path -Path $AutorunsDirectory)) {
    Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Creating Autoruns directory"
    New-Item -Path $AutorunsDirectory -ItemType Directory -Force | Out-Null
}  # End If

$LogFileExists = Get-EventLog -List -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.LogDisplayName -eq "Autoruns" }
If (!($LogFileExists)) {
    Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Creating Autoruns Event Log"
    New-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog"
    Limit-EventLog -LogName "Autoruns" -OverflowAction OverwriteAsNeeded -MaximumSize ($MaxLogSizeKB * 1KB)
}  # End If

Try {

    $OSArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem).OSArchitecture
    $AutorunsExecutable = "Autorunsc64.exe"
    If ($OSArchitecture -notmatch "64") {
        $AutorunsExecutable = "Autorunsc.exe"
    }  # End If

    $AutorunsPath = Join-Path -Path $AutorunsDirectory -ChildPath $AutorunsExecutable
    $AutorunsCsv = Join-Path -Path $AutorunsDirectory -ChildPath "AutorunsOutput.csv"
    If (!(Test-Path -Path $AutorunsPath)) {
        Throw "Autoruns executable was not found at $AutorunsPath"
    }  # End If

    Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Executing Autoruns"
    $Proc = Start-Process -FilePath $AutorunsPath -ArgumentList @(
        '-nobanner',
        '/accepteula',
        '-a', '*',
        '-c',
        '-h',
        '-s',
        '-v',
        '-vt', '*'
    ) -RedirectStandardOut $AutorunsCsv -WindowStyle Hidden -PassThru

    $Proc.WaitForExit()
    If ($Proc.ExitCode -ne 0) {
        Throw "Autoruns exited with code $($Proc.ExitCode)"
    }  # End If

    $AutoRunsArray = Import-Csv -Path $AutorunsCsv -Delimiter ','
    ForEach ($Item in $AutoRunsArray) {

        $Data = $Item | Out-String -Width 1000
        Write-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog" -EntryType Information -EventId 1 -Message $Data

    }  # End ForEach

    $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    $ComputerName = "$($ComputerSystem.DNSHostName).$($ComputerSystem.Domain)"
    $DomainFQDN = $ComputerName.Split(".")[1..($ComputerName.Split(".").Length - 1)] -Join "."
    $LocalGroups = Get-LocalGroup | Where-Object -FilterScript {
        ($_.SID -Match "S-1-5-32-555") -or
        ($_.SID -Match "S-1-5-32-544") -or
        ($_.SID -Match "S-1-5-32-562")
    }  # End Where-Object

    $LocalGroups | ForEach-Object -Process {

        $GroupName = $_.Name
        Get-LocalGroupMember -Name $GroupName | Where-Object -FilterScript {
            $_.PrincipalSource -Match "ActiveDirectory"
        } | ForEach-Object -Process {
            $PrincipalName = $_.Name.Split("\")[1] + "@$DomainFQDN"
            $Data = @"
GroupName: $GroupName
PrincipalType: $($_.ObjectClass)
PrincipalName: $PrincipalName
"@
            Write-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog" -EntryType Information -EventId 2 -Message $Data
        }  # End ForEach-Object

    }  # End ForEach-Object
    $AutoRunsArray | Export-Csv -Path $AutorunsCsv -Delimiter ',' -NoTypeInformation -Force

} Catch {
    Throw "[x] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Failed To Collect Autoruns Data. $($_.Exception.Message)"
}  # End Try Catch
