# This requires only AzureADPreview PowerShell module. If AzureAD PowerShell module is installed as well this script will not work because of the shared cmdlets
Import-Module -Name AzureADPreview
$Date = Get-Date -Date (Get-Date).AddHours(-24) -Format "yyyy-MM-ddThh:mm:ss"

# Below is an example of a filter that can be used to refine the logins you want information on. Modify this to whatever you need                                                                                                                                                     # Eliminates any IPv6 addresses from results                       
$Filter = "createdDateTime gt $Date.0Z and status/errorCode eq 0 and location/city ne 'Colorado Springs' and location/city ne 'Newark' and location/city ne 'New York' and IpAddress ne '5.5.5.5' and IpAddress ne '6.6.6.6' and IpAddress ne '7.7.7.7' and IpAddress ne '8.8.8.8'" | Where-Object { $_.IpAddress -notlike "*:*"} | Select-Object -Property AppDisplayName,UserPrincipalName,CorrelationId,IpAddress,Status,Location


# I used this script to generate the below info and hide the password for the Azure global admin https://github.com/tobor88/PowerShell/blob/master/Hide-PowerShellScriptPassword.ps1
# I used this cmdlet to ensure this script has strong permissions https://github.com/tobor88/BTPS-SecPack/blob/master/Hardening%20Cmdlets/Set-SecureFilePermissions.ps1
$PlainUser = "azure-global-admin@domain.com"
$FileVar = "11111111111111111111"  # This value is the Generated file name after using https://github.com/tobor88/PowerShell/blob/master/Hide-PowerShellScriptPassword.ps1
$PasswordFile = "C:\Users\Public\Documents\Keys\$FileVar.AESpassword.txt"
$KeyFile = "C:\Users\Public\Documents\Keys\$FileVar"
$Key = Get-Content -Path $KeyFile
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $PlainUser, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)

Write-Output "[*] Authenticating to Azure"
Connect-AzureAD -Credential $Cred


Write-Output "[*] Searching Azure Sign In logs for Successul sign ins that occurred in unusual locations"
$SuccessfulSignIns = Get-AzureADAuditSignInLogs -Filter $Filter


Write-Output "[*] Analyzing results"
$Obj = @()
$UserList = $SuccessfulSignIns | Select-Object -Property UserPrincipalName -Unique
ForEach ($User in $UserList) {

    $UserPrincipalName = $User.UserPrincipalName
    $IpAddresses = $SuccessfulSignIns | Where-Object { $_.UserPrincipalName -eq $UserPrincipalName } | Select-Object -Property IpAddress -Unique
    
    $ReturnResults = @()
    ForEach ($IpAddress in $IpAddresses) {

        $ReturnResults += $SuccessfulSignIns | Where-Object { $_.UserPrincipalName -eq $UserPrincipalName -and $_.IpAddress -eq $IpAddress.IpAddress}
        $IPCount = ($ReturnResults | Where-Object { $_.IpAddress -eq $IpAddress.IpAddress }).Count
        If (!$IPCount) { $IPCount = 1 }
        $LocationInfo = $ReturnResults | Where-Object { $_.IpAddress -eq $IpAddress.IpAddress } | Select-Object -ExpandProperty Location -First 1
        $App = $ReturnResults | Where-Object { $_.IpAddress -eq $IpAddress.IpAddress } | Select-Object -ExpandProperty AppDisplayName -First 1

        $Obj += New-Object -TypeName PSObject -Property @{App=$App;UserPrincipalName=$UserPrincipalName;IpAddress=$IpAddress.IpAddress;'Login Count'=$IPCount;City=$LocationInfo.City;State=$LocationInfo.State;Country=$LocationInfo.CountryOrRegion}

    }  # End ForEach

}  # End ForEach

$Results = $Obj | Select-Object -Property "UserPrincipalName","Login Count","IpAddress","City","State","Country" | Sort-Object -Property UserPrincipalName,IpAddress,City

$Css = @"
<style>
table {
    font-family: verdana,arial,sans-serif;
        font-size:11px;
        color:#333333;
        border-width: 1px;
        border-color: #666666;
        border-collapse: collapse;
}
th {
        border-width: 1px;
        padding: 8px;
        border-style: solid;
        border-color: #666666;
        background-color: #dedede;
}
td {
        border-width: 1px;
        padding: 8px;
        border-style: solid;
        border-color: #666666;
        background-color: #ffffff;
}
</style>
"@ # End CSS 

$PreContent = "<Title>Azure Review Sign Ins</Title>"
$NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
$PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
$MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on user sign in locations over the past 24 hours<br><br><hr><br><br>" | Out-String

Send-MailMessage -From FromEmail -To ToEmail -Subject "Daily Azure Sign In Review" -BodyAsHtml -Body $MailBody -SmtpServer UseSmtpServer -Credential $Credential -UseSsl -Port 587 -Priority Normal
