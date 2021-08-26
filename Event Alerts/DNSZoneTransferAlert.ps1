$Events = Get-WinEvent -FilterHashtable @{LogName='DNS Server';ID='6001'} -MaxEvents 1

If ($Events) {
    
    $Results = $Events | ForEach-Object {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, Domain, InitiatedBy, DC, Date, Message
            $Obj.EventID = $_.Id
            $Obj.Domain = $_.Properties[1].Value
            $Obj.InitiatedBy = $_.Properties[2].Value
            $Obj.DC = $_.MachineName
            $Obj.Date = $_.TimeCreated
            $Obj.Message = "DNS Zone Transfer has occured"
            
            $Obj

    }  # End ForEach-Object

}  # End If

# TEAMS POST
If ($Results) {

    $Domain = $Obj.Domain
    $EventID = $Obj.EventID
    $InitiatedBy = $Obj.InitiatedBy
    $DC = $Obj.DC
    $Date = $Obj.Date.ToLongDateString()
    $Message = $Obj.Message
    $WebhookUrl = 'WEBHOOK_URL_REPLACE'
    $Body = ConvertTo-Json -Depth 8 @{
        title = "DNS Zone Transfer Alert"
        text = "
        DC        = $DC 
        Initiator = $InitiatedBy 
        Domain    = $Domain
        Time      = $Date
        Message   = $Message"
        summary = 'DNS zone Transfer Alert'
        potentialAction =   @(
                                @{
                                    '@context'  = 'http://schema.org'
                                    '@type' = 'ViewAction'
                                    name = 'Elasticsearch for Correlation Events'
                                    target = @("SIEM TOOL LINK")
                                }
                            ) 
    }  # End Body

    # Post the JSON Array Object to the Webhook Connector URI
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Body -ContentType 'application/json'

}  # End If
