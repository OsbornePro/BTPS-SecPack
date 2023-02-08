Function Test-IfPasswordIsExposedOnline {
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
