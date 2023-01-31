Function Set-SecureFilePermissions {
<#
.SYNOPSIS
This cmdlet was created to set retrictive permissions on scripts that were created to run as tasks on servers.


.DESCRIPTION
Running this command against a file or directory will modify the permissions by removing any pre-existing permissions and adding the defined allowed users.


.PARAMETER Username
Defines the users that should be given Full Control over a file

.PARAMETER Owner
Defines the user who should be the owner of an NTFS file. The default value is 'BUILTIN\Administrators'

.PARAMETER Path
Define the local path to a file you want the permissions changed on. Modifying permissions on a remote machine will require the path to that file as if you were on that machine.

.PARAMETER ComputerName
This parameter defines remote devices that have a file on them you want the permissions changed on. Separate multiple values with a comma

.PARAMETER UseSSL
This parameter is used to define using WinRM over HTPS when the ComputerName switch parameter is a remote device


.EXAMPLE
Set-SecureFilePermissions -Username 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc' -Path C:\Temp\secretfile.txt
# This example gives SYSTEM, Administrators, Network Configuration Operators, MpsSvc exclusive access to secretfile.txt and sets the Administrators group as the owner

.EXAMPLE
Set-SecureFilePermissions -Username 'NT AUTHORITY\SYSTEM','BUILTIN\Administrators' -Path "C:\Temp\derp.log" -Owner 'BUILTIN\SYSTEM' -ComputerName 10.0.0.1 -UseSSL
# This example gives administrators and system permissions to the derp.log file and makes SYSTEM the owner on the remote device 10.0.0.1 using a WinRM over HTTPS connection

.EXAMPLE
$Files = Get-ChildItem -Path $env:USERPROFILE\Documents\Scripts -Recurse -Filter *.ps1
$Files | ForEach-Object { Set-SecureFilePermissions -Username 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'CONTOSO\Mike' -Path $_.FullName -Owner 'CONTOSO\Mike' -Verbose }
# This example sets SYSTEM, Administrators, and Mike to have permissions to any ps1 files in the directory defined and sets Mike as the owner.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String, System.Array


.OUTPUTS
None


.LINK
https://osbornepro.com
https://btpssecpack.osbornepro.com
https://encrypit.osbornepro.com
https://writeups.osbornepro.com
https://github.com/OsbornePro
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Add a user or list of users who should have permisssions to an NTFS file`n[E] EXAMPLE: 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc'")]  # End Parameter
            [Alias('User')]
            [String[]]$Username,

            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="`n[H] Define the path to the NTFS item you want to modify the entire permissions on `n[E] EXAMPLE: C:\Temp\file.txt")]  # End Parameter
            [String[]]$Path,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]
            [String]$Owner = 'BUILTIN\Administrators',

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Alias('cn')]
            [String[]]$ComputerName = $env:COMPUTERNAME,
            
            [Parameter(
                Mandatory=$False
            )]  # End Parameter
            [Switch][Bool]
            $UseSSL
        )  # End param

    $SSL = $False
    If ($UseSSL.IsPresent) {
    
        $SSL = $True
        
    }  # End If
    
    If ($ComputerName -eq $env:COMPUTERNAME) {

        Write-Verbose -Message "Modifying access rule proteciton"
        $Acl = Get-Acl -Path "$Path"
        $Acl.SetAccessRuleProtection($True, $False)

        ForEach ($U in $Username) {

            Write-Verbose -Message "Adding $U permissions for $Path"
            $Permission = $U, 'FullControl', 'Allow'
            $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
            $Acl.AddAccessRule($AccessRule)

        }  # End ForEach

        Write-Verbose -Message "Changing the owner of $Path to $Owner"
        $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount("$Owner")))
        $Acl | Set-Acl -Path "$Path"

    } Else {

        ForEach ($C in $ComputerName) {

            Invoke-Command -HideComputerName $C -UseSSL:$SSL -ScriptBlock {

                Write-Verbose -Message "Modifying access rule proteciton"
                $Acl = Get-Acl -Path "$Using:Path"
                $Acl.SetAccessRuleProtection($True, $False)

                ForEach ($U in $Using:Username) {

                    Write-Verbose -Message "Adding $U permissions for $Using:Path"
                    $Permission = $U, 'FullControl', 'Allow'
                    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
                    $Acl.AddAccessRule($AccessRule)

                }  # End ForEach

                Write-Verbose -Message "Changing the owner of $Using:Path to $Using:Owner"
                $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount("$Using:Owner")))
                $Acl | Set-Acl -Path "$Using:Path"

            }  # End Invoke-Command

        }  # End ForEach

    }  # End If Else

}  # End Function Set-SecureFilePermissions
