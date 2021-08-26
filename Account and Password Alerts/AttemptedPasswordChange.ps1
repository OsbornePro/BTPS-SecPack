# Alert IT when a users password is changed
$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4723 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1
$ArrayTable = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'

If ($Events) {

    $Events | ForEach-Object {

        $Section = @{
          activityTitle = "User Changed Password"
          activitySubtitle = "$($_.Properties[0].Value)"
          activityText  = "$($_.Properties[0].Value) changed password at $($_.TimeCreated.ToString())"
          activityImage = ""
	      facts		  = @(
                @{
                        name = "EventID: "
                        value = $_.Id
                    }
                @{
                        name = "User: "
                        value = $_.Properties[0].Value
                    },
                @{
                        name = "SID: "
                        value = $_.Properties[2].Value
                    },
                @{
                        name = "Computer Name: "
                        value = $_.MachineName
                    },
                @{
                        name = "Date: "
                        value = $_.TimeCreated.ToString()
                    },
                @{
                        name = "Message"
                        value = "User changed password"
                    }
            )  # End Facts

	    }  # End Section

	    $ArrayTable.Add($Section)

    }  # End ForEach-Object

    $Body = ConvertTo-Json -Depth 8 @{
	    title = "User Changed Password"
	    text  = "There are $($ArrayTable.Count) passwords changed by $($_.Properties[0].Value)"
	    sections = $ArrayTable
        potentialAction =   @(
                        @{
                            '@context'  = 'http://schema.org'
                            '@type' = 'ViewAction'
                            name = 'Elasticsearch for Correlation Events'
                            target = @("https://selenium.usav.org:5601/")
                        },
                        @{
                            '@context'  = 'http://schema.org'
                            '@type' = 'ViewAction'
                            name = 'Splunk for Correlation Events'
                            target = @("SIEM TOOL LINK")
                        }
                    )  # End Potential Actions
    }  # End Body


    $WebhookUrl = 'WEBHOOK_URL_REPLACE'
    
    # Post the JSON Array Object to the Webhook Connector URI
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Body -ContentType 'application/json'

}  # End If
