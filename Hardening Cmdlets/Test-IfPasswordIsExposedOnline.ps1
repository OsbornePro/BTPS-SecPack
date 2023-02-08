Function Test-IfPasswordIsExposedOnline {
<#
.SYNOPSIS
This cmdlet is used to check haveibeenpwned.com for exposed passwords.


.DESCRIPTION
Enter your password as a secure string. It is then hashed to perform a query to haveibeenpwned.com returning results if found


.PARAMETER Password
Enter your password as in SecureString format using ConvertTo-SecureString or Read-Host -AsSecureString


.EXAMPLE
Test-IfPasswordIsExposedOnline -Password (Read-Host -Prompt "Enter your password" -AsSecureString)


.INPUTS
System.Security.SecureString


.OUTPUS
PSCustomObject


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
  [CmdletBinding()]
    param (
      [Parameter(
          Position=0,
          Mandatory=$True,
          ValueFromPipeline=$True,
          ValueFromPipelineByPropertyName=$False,
          HelpMessage="Enter your password as a secure string (Read-Host -Prompt 'Enter your password' -AsSecureString")]  # End Parameter
        [System.Security.SecureString]$Password
    )  # End param
  
BEGIN {

    $Output += @()
    [System.Net.ServicePointManager]::SecurityProtocol = 'Tls12'

} PROCESS {

    Write-Verbose -Message "Translating secure string in memory"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $PlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    Write-Verbose -Message "Converting password to a SHA1 hash value"
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $InputStream = [System.IO.MemoryStream]::new($Bytes)
    $Hash = Get-FileHash -Algorithm 'SHA1' -InputStream $InputStream
    $InputStream.Close()
    $InputStream.Dispose()
    $First5Chars = $Hash.Hash.SubString(0,5)
    $HashQuery = $Hash.Hash.Remove(0, 5)

    $Uri = "https://api.pwnedpasswords.com/range/$First5Chars"
    $Response = (Invoke-RestMethod -Uri $Uri -UseBasicParsing -Method GET).Split("$([System.Environment]::NewLine)")
    $ExposedResult = $Response -like "*$HashQuery*"
    $IsExposed = $False
    If ($ExposedResult) {

        $IsExposed = $True

    }  # End If

    $Output += New-Object -TypeName PSCustomObject -Property @{
        IsExposed=$IsExposed;
        ExposureCount=$ExposedResult.Split(':')[-1];
        SHA1Hash=$Hash.Hash;
    }  # End New-Object -Property

} END {

    Return $Output

}  # End B P E

}  # End Function Test-IfPasswordIsExposedOnline
