<#
.SYNOPSIS
This cmdlet is used to reset kerberos keys used by an online Exchange environement.

.DESCRIPTION
This cmdlet was created for sysadmins and does not require any switches. Best used if run automatically using Windows Task Scheduler.

.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.EXAMPLE
Reset-KerbKeys -Verbose


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
None


.OUTPUTS
None

#>
Function Reset-KerbKeys {
    [CmdletBinding()]
        param()

  BEGIN {

      $To = "alert.email@osbornepro.com"
      $From = "alerter@osbornepro.com"
      $SmtpServer = "smtp.derp.com"

      $User = "Robo.username@osbornepro.com"
      $PasswordFile = "C:\Users\Public\Documents\Keys\passwordfile.txt"
      $KeyFile = "C:\Users\Public\Documents\Keys\passwordkeyfile.txt"
      $Key = Get-Content -Path $KeyFile
      $Cred1 = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, (Get-Content -Path $PasswordFile | ConvertTo-SecureString -Key $key)

      Install-Module AzureAD -Credential $Cred1 -Force

      Write-Verbose "Discovering location of AzureADSSO.psd1"

      $AzureFile = (Get-ChildItem -Path "C:\" -Filter "AzureADSSO.psd1" -Recurse -Force -ErrorAction SilentlyContinue).FullName

  } # End Begin

  PROCESS {

  # USER1 needs to be a global administrator

      Write-Verbose "Importing AzureADSSO.psd1 from directory $AzureFile"

      Import-Module "$AzureFile" -Force

      New-AzureADSSOAuthenticationContext -CloudCredentials $cred1

      Write-Verbose 'Checking for errors.'

      Update-AzureADSSOForest -OnPremCredentials $cred1

  } # End Process

  END {

      $Status = Get-AzureADSSOStatus

      Send-MailMessage -To $To -From $From -Subject "Kerberos Keys Rotated" -Body "$Satus" -SmtpServer $SmtpServer -Priority Normal

   } # End End

} # End Function
