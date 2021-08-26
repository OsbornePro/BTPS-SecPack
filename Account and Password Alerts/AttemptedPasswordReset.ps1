# Alert IT when a users password is changed by another account
$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4724 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1
$ArrayTable = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'

If ($Events) {

    $Events | ForEach-Object {

        $Section = @{
          activityTitle = "Admin Changed a Users Password"
          activitySubtitle = "$($_.Properties[0].Value)"
          activityText  = "$($_.Properties[4].Value) changed $($_.Properties[0].Value) password at $($_.TimeCreated.ToString())"
          activityImage = ""
	      facts		  = @(
                @{
                        name = "EventID: "
                        value = $_.Id
                    }
                @{
                        name = "Effected User: "
                        value = $_.Properties[0].Value
                    },
                @{
                        name = "Executing User: "
                        value = $_.Properties[4].Value
                    },
                @{
                        name = "DC: "
                        value = $_.MachineName
                    },
                @{
                        name = "Date: "
                        value = $_.TimeCreated.ToString()
                    },
                @{
                        name = "Message"
                        value = "Admin changed a users password"
                    }
            )  # End Facts

	    }  # End Section

	    $ArrayTable.Add($Section)

    }  # End ForEach-Object

    $Body = ConvertTo-Json -Depth 8 @{
	    title = "Admin Changed a Users Password"
	    text  = "There are $($ArrayTable.Count) passwords changed by $($_.Properties[4].Value)"
	    sections = $ArrayTable
        potentialAction =   @(
                        @{
                            '@context'  = 'http://schema.org'
                            '@type' = 'ViewAction'
                            name = 'SIEM for Correlation Events'
                            target = @("SIEM TOOL LINK")
                        }
                    )  # End Potential Actions
    }  # End Body


    $WebhookUrl = 'WEBHOOK_URL_REPLACE'
    
    # Post the JSON Array Object to the Webhook Connector URI
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Body -ContentType 'application/json'

}  # End If
