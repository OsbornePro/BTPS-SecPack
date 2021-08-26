$Events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=4741;StartTime=(Get-Date).AddHours("-1")} | Select-Object -First 1

$Results = $Events | ForEach-Object {

            $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, UserName, DomainName, MachineName, Date, Message
            $Obj.EventID = $_.Id
            $Obj.UserName = $_.Properties[0].Value
            $Obj.DomainName = $_.Properties[1].Value
            $Obj.MachineName = $_.Properties[26].Value
            $Obj.Date = $_.TimeCreated
            $Obj.Message = "A new computer object was created"
            
            $Obj

}  # End ForEach-Object

# TEAMS POST
If ($Results) {

    $Username = $Obj.Username
    $EventID = $Obj.EventID
    $Domain = $Obj.DomainName
    $Machine = $Obj.MachineName
    $AuthType = $Obj.Type
    $Date = $Obj.Date.ToLongDateString()
    $Message = $Obj.Message
    $WebhookUrl = 'WEBHOOK_URL_REPLACE'
    $Body = ConvertTo-Json -Depth 8 @{
        title = "New Computer Joined Domain"
        text = "
        Event ID = $EventID
        Username = $Username 
        Domain   = $Domain
        Device   = $Machine
        Time     = $Date
        Message  = $Message"
        summary = 'New Computer Joined Domain'
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
