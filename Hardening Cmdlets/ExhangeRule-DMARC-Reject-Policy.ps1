# Microsoft does not do what your DMARC policy tells it to do and requires a custom Transport Rule to reject failed DMARC emails

$RuleName = "DMARC Reject Policy (Microsoft Only)"
$Credential = Get-Credential -Message "Enter Office365 Global Administrator credentials"
$HeaderContainsMessageHeader = "Authentication-Results"
$HeaderContainsWords = "dmarc=fail action=oreject"
$RejectMessageReasonText = "Unauthenticated email is not accepted due to sender's domain's DMARC policy"
$Comments = "Microsoft does not reject emails based on DNS DMARC policies and needs to be configured to do so using this transport rule"

Write-Output "[*] Getting the Exchange Online cmdlets required to create the rule"
Import-Module -Name ExchangeOnlineManagement
Connect-ExchangeOnline -Credential $Credential -ConnectionUri "https://outlook.office365.com/powershell-liveid/" -ExchangeEnvironmentName 'O365Default'

If (!(Get-TransportRule | Where-Object -FilterScript {$_.Identity -Contains $RuleName})) {

    Write-Output "[*] Rule not found, creating rule $RuleName"
    New-TransportRule -Name $RuleName -Priority 0 -RejectMessageReasonText $RejectMessageReasonText -HeaderContainsMessageHeader $HeaderContainsMessageHeader -HeaderContainsWords $HeaderContainsWords -Comments $Comments

} # End If
Else {

    Write-Output "[*] Rule found, updating rule $RuleName"
    New-TransportRule -Name $RuleName -Priority 0 -RejectMessageReasonText $RejectMessageReasonText -HeaderContainsMessageHeader $HeaderContainsMessageHeader -HeaderContainsWords $HeaderContainsWords -Comments $Comments

} # End Else
