Function Hide-PasswordKey {
<#
.SYNOPSIS
This cmdlet is used to generate an AES key and Base64 encrypted Password value to allow storing objfuscated passwords in a script

.DESCRIPTION
Return a Key value and base64 encoded encrypted password value to use in saving objfuscated passwords for use in a script.


.PARAMETER Password
Enter the password value you want to protect using a secure string

.PARAMETER Path
Define the directory location you wish to save your base64 encoded encrypted password value and AES key files

.PARAMETER HowTo
Tells the cmdlet to return information on how to use the returned values


.EXAMPLE
Hide-PasswordKey -Password (ConvertTo-SecureString -String 'Password123!' -AsPlainText -Force)
# This example returns copy and paste values in the output you can use in your script to obfuscate a password

.EXAMPLE
Hide-PasswordKey -Password (ConvertTo-SecureString -String 'Password123!' -AsPlainText -Force) -Path $env:USERPROFILE\PasswordKeys
# This example creates a file containing an encrypted AES password value encoded in based64 and a file containing the AES key used to encrypt the Bas64 value in the -aes.txt file. It also requires elevated permissions to read the generated files

.EXAMPLE
Hide-PasswordKey -HowTo
# This example returns information on how to use the generated values from this cmdlet


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://github.com/tobor88
https://github.com/osbornepro
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
System.SecureString


.OUTPUTS
System.String, PSCustomObject
#>
    [CmdletBinding(DefaultParameterSetName="Var")]
        param(
            [Parameter(
                ParameterSetName="Var",
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                HelpMessage="Enter the secure password value you want to generate an AES encrypted value and key for ")]  # End Parameter
            [Parameter(
                ParameterSetName="File",
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                HelpMessage="Enter the secure password value you want to generate an AES encrypted value and key for ")]  # End Parameter
            [SecureString]$Password,

            [Parameter(
                ParameterSetName="File",
                Position=1,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$Path,

            [Parameter(
                ParameterSetName="HowTo",
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$HowTo
        ) # End param

BEGIN {

    Write-Verbose -Message "Generating values to protect password"
    $Obj = @()

} PROCESS {

    If ($PSCmdlet.ParameterSetName -eq "File") {

        $Date = (Get-Date).Ticks
        $KeyFilePath = "$($Path)\$($Date)-key.txt"
        $AESPasswordPath = "$($Path)\$($Date)-aes.txt"

        Write-Verbose -Message "Creating the Key and AES files"
        New-Item -ItemType File -Path $KeyFilePath -Force
        New-Item -ItemType File -Path $AESPasswordPath -Force

    }  # End If

    If ($HowTo.IsPresent) {

        Write-Output -InputObject "1.) Build a `$Credential object using generated files."
        Write-Output -InputObject "`t`$User = `"account@osbornepro.com`""
        Write-Output -InputObject "`t`$PasswordFile = `"`$env:TEMP\637997375371890206-aes.txt`""
        Write-Output -InputObject "`t`$KeyFile = `"`$env:TEMP\637997375371890206-key.txt`""
        Write-Output -InputObject "`t`$Key = Get-Content -Path `$KeyFile"
        Write-Output -InputObject "`t`$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList `"account@osbornepro.com`", (Get-Content -Path `$PasswordFile | ConvertTo-SecureString -SecureKey (Get-Content -Path `$KeyFile`"))"
        Write-Output -InputObject "`n2.) Build a credential object using returned values in your file. The script containing your Base64 and Key values should like the below."
        Write-Output -InputObject "`t`$Base64 = `"76492d1116743f0423413b16050a5345MgB8AFgAYQBvACsAMwBNAFcAOQA1AFYAbgAvAGUAeABCAEEAMAB4AEkAWQAvAEEAPQA9AHwANgA1ADgAMQBhAGEAMwAyADEANABjADYAMQAyADAAOQBkAGQANQBjADcAYwAxADIAOAA4AGIAYgBmADcAYQA1ADkANQA4ADYAZAAyADEANAAzADcANgA3ADgAZgA4ADAAMQAwADMAYgAxAGQANwAxADIAYgBmAGQAZABkAGYANgBjADgANgAxADYANgA3AGYAYgA2ADYAZQBjADkAMABiADkAOABiAGMAZAA2ADAAYgBmAGMAOQBhAGIAMABlADAA`""
        Write-Output -InputObject "`t`$Key = `"`@(105, 85, 8, 171, 52, 213, 195, 166, 125, 30, 36, 236, 228, 184, 116, 121, 208, 187, 142, 159, 104, 204, 138, 116, 121, 75, 107, 28, 64, 6, 195, 191)`""
        Write-Output -InputObject "`t`$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList `"account@osbornepro.com`", (`$Base64 | ConvertTo-SecureString -SecureKey `$Key`")) `n"
        Return

    } Else {

        Write-Verbose -Message "Creating a random 32-bit key. (Maximum Key Size is 32)"
        $Key = New-Object -TypeName System.Byte[] -ArgumentList 32
        [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($Key)
        $Base64 = ConvertFrom-SecureString -SecureString $Password -Key $Key 

        If ($PSCmdlet.ParameterSetName -eq "File") {

            $Key | Out-File -FilePath $KeyFilePath -Encoding UTF8 -Force -Confirm:$False
            $Base64 | Out-File -FilePath $AESPasswordPath -Encoding UTF8 -Force -Confirm:$False

            Write-Verbose "Setting secure file permissions on the newly created files containing your encrypted password and keys"
            $Acl = Get-Acl -Path @($KeyFilePath, $AESPasswordPath)
            $Acl.SetAccessRuleProtection($True, $False)

            $Permission = 'NT AUTHORITY\SYSTEM', 'FullControl', 'Allow'
            $Acl.AddAccessRule($(New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission))
            $Permission = 'BUILTIN\Administrators', 'FullControl', 'Allow'
            $Acl.AddAccessRule($(New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission))
            $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount('BUILTIN\Administrators')))
            $Acl | Set-Acl -Path @($KeyFilePath, $AESPasswordPath)

        }  # End If

        $KeyString = ($Key | Out-String).Replace("$([System.Environment]::NewLine)",", ")
        $KeyString = ("@($($KeyString))").Replace(', )',')')

        $Obj += New-Object -TypeName PSCustomObject -Property @{Key=$Key; KeyString=$KeyString; Base64=$Base64}
        Write-Output -InputObject "`nCOPY AND PASTE KEY VALUE: $($KeyString)"
        Write-Output -InputObject "COPY AND PASTE BASE64 VALUE: $($Base64)"

    }  # End If Else

} END {

    Return $Obj

} # End BPE

} # End Function Hide-PasswordKey
