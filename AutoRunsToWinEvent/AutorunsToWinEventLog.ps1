#Requires -Version 3.0
#Requires -RunAsAdministrator
<#
.SYNOPSIS
This script executes the Sysinternals Autoruns CLI utility and saves the output to a CSV. The resulting CSV entries are written to a Windows Event Log called "Autoruns"


.DESCRIPTION
Configure a new logging entry in the Windows Event log to keep track of registry values through the Sysinternals utility AutoRuns


.PARAMETER AutorunsDirectory
Define the directory to save the Autoruns related files too

.PARAMETER MaxLogSize
Define the max log size for the Autoruns Windows Event Log entry to be created

.NOTES
Authors: Chris Long (@Centurion), Andy Robbins (@_wald0), Robert Osborne

.LINK
https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog
https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
https://github.com/tobor88
https://github.com/osbornepro
https://www.powershellgallery.com/profiles/tobor
https://osbornepro.com
https://writeups.osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges


.INPUTS
None


.OUTPUS
None
#>
[CmdletBinding()]
    param(
        [Parameter(
            Position=0,
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False
        )]  # End Parameter
        [String]$AutorunsDirectory = "$env:ProgramFiles\AutorunsToWinEventLog",
    
        [Parameter(
            Position=1,
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False
        )]  # End Parameter
        [ValidateRange(1, 16776960)]
        [Int64]$MaxLogSize = 4194240
    )  # End param

BEGIN {

    $LogfileExists = Get-Eventlog -List -Verbose:$False | Where-Object {$_.logdisplayname -eq "Autoruns"}
    If (!($LogfileExists)) {

      Write-Verbose -Message "[v] Creating the Event Log View entry AutorunsToWinEventLog"
      New-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog" -Verbose:$False
      Limit-EventLog -LogName "Autoruns" -OverflowAction OverWriteAsNeeded -MaximumSize "$($MaxLogSize)KB" -Verbose:$False

    }  # End If
    
} PROCESS {

    $OSArchitecture = (Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$False).OSArchitecture
    $AutorunsCsv = "$($AutorunsDirectory)\AutorunsOutput.csv"
    $AutorunsExecutable = "Autorunsc64.exe"
    If ($OSArchitecture -notmatch "64") {

        $AutorunsExecutable = "Autorunsc.exe"

    }  # End If

    $Proc = Start-Process -FilePath "$($AutorunsDirectory)\$($AutorunsExecutable)" -ArgumentList @('-nobanner', '/accepteula', '-a *', '-c', '-h', '-s', '-v', '-vt', '*') -RedirectStandardOut $AutorunsCsv -WindowStyle Hidden -Passthru -Verbose:$False
    $Proc.WaitForExit()
    $AutoRunsArray = Import-Csv -Delimiter ',' -Path $AutoRunsCsv -Verbose:$False
    
    Foreach ($Item in $AutoRunsArray) {

        $Item = Write-Output -InputObject $Item | Out-String -Width 1000
        Write-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog" -EntryType Information -EventId 1 -Message $Item -Verbose:$False

    }  # End ForEach
    
    $ComputerName = "$((Get-CimInstance -ClassName Win32_ComputerSystem -Verbose:$False).DNSHostName).$((Get-CimInstance -ClassName Win32_ComputerSystem -Verbose:$False).Domain)"
    $DomainFQDN = $ComputerName.Split(".")[1..($ComputerName.Split(".").length-1)] -Join "."

    $LocalGroups = Get-LocalGroup -Verbose:$False | Where-Object -FilterScript { ($_.SID -Match "S-1-5-32-555") -or ($_.SID -Match "S-1-5-32-544") -or ($_.SID -Match "S-1-5-32-562") }
    $LocalGroups | ForEach-Object {

        $GroupName = $_
        Get-LocalGroupMember -Name $GroupName -Verbose:$False | Where-Object { $_.PrincipalSource -Match "ActiveDirectory" } | ForEach-Object {

            $PrincipalName = $_.Name.Split("\")[1] + "@" + $DomainFQDN
            $Member = New-Object -TypeName PSObject
            $Member | Add-Member Noteproperty 'GroupName' $GroupName
            $Member | Add-Member Noteproperty 'PrincipalType' $_.ObjectClass
            $Member | Add-Member Noteproperty 'PrincipalName' $principalname

            $Data = @"
GroupName: $($Member.GroupName)
PrincipalType: $($Member.PrincipalType)
PrincipalName: $($Member.PrincipalName)
"@

            Write-EventLog -LogName "Autoruns" -Source "AutorunsToWinEventLog" -EntryType Information -EventId 2 -Message $Data -Verbose:$False

        }  # End ForEach-Object

    }  # End ForEach-Object

    Write-Verbose -Message "[v] Creating a CSV File containing autoruns information for the day"
    $AutoRunsArray | Export-Csv -Path $AutorunsCsv -Delimiter ',' -NoTypeInformation -Force -Verbose:$False

} END {

}  # End B P E
