<#
.SYNOPSIS
This cmdlet is for importing a scheduled task onto local or remote devices


.DESCRIPTION
This uses the Register-ScheduledTask cmdlet to import a scheduled task from a network share into local or remote devices


.PARAMETER Path
Defines the full path and file name definition for the .xml file to import. If remote devices are being used this files location should be a share accessible by them

.PARAMETER TaskName
Define a display name for the task once imported

.PARAMETER TaskPath
Define the path the task should be imported to. Default value is the root directory \

.PARAMETER User
Define a user the task should run as. The default value is the SYSTEM user.

.PARAMETER ComputerName
Indicates the device(s) that should have the scheduled task file imported


.EXAMPLE
Import-ScheduledTask -Path C:\Windows\Temp\TaskImportName.xml -TaskName "My Task" -TaskPath "\" -User SYSTEM
# This example imports a scheduled task xml file and creates a task on the local device

.EXAMPLE
Import-ScheduledTask -Path C:\Windows\Temp\TaskImportName.xml -TaskName "My Task" -TaskPath "\" -User SYSTEM -ComputerName 'DC01.osbornepro.com', '10.0.1.1' 
# This example imports a scheduled task xml file and creates a task on DC01.domain.com and 10.0.1.1


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String System.Array


.OUTPUTS
Microsoft.Management.Infrastructure.CimInstance#MSFT_ScheduledTask


.LINK
https://roberthosborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
#>
Function Import-ScheduledTask {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define the full path and file name to the task xml file you exported from task scheduler. This can be a network location`n[E] EXAMPLE: C:\Temp\taskfile.xml")]  # End Parameter
            [Alias('FilePath')]
            [String]$Path,

            [Parameter(
                Position=1,
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Define a display name for the task `n[E] EXAMPLE: 'Run Program At Startup'")]  # End Parameter
            [String]$TaskName,

            [Parameter(
                Position=2,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$TaskPath = "\",

            [Parameter(
                Position=3,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$User = 'NT AUTHORITY\SYSTEM',

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]  # End Parameter
            [Alias('cn')]
            [String[]]$ComputerName = $env:COMPUTERNAME
        )  # End param

    
    $Xml = Get-Content -Path $Path | Out-String

    ForEach ($C in $ComputerName)
    {

        Write-Verbose "Creating task $TaskName on $C in the task location $TaskPath"

        Register-ScheduledTask -Xml $Xml -TaskName $TaskName -TaskPath $TaskPath -User $User –Force

    }  # End ForEach

}  # End Function Import-ScheduledTask