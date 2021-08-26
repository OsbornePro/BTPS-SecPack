# Alerrts IT when a user account is unlocked
$Event = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4767 and TimeCreated[timediff(@SystemTime) <= 86400000]]]' -MaxEvents 1
$ArrayTable = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'

If ($Events) {

    $Events | ForEach-Object {

        $Section = @{
          activityTitle = "Account Unlocked"
          activitySubtitle = "$($_.Properties[0].Value)"
          activityText  = "User account $($_.Properties[0].Value) was unlocked at $($_.TimeCreated.ToString())"
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
                        name = "Process ID: "
                        value = $_.ProcessID
                },
                @{
                        name = "Device Name: "
                        value = $_.MachineName
                    },
                @{
                        name = "Date: "
                        value = $_.TimeCreated.ToString()
                    },
                @{
                        name = "Message"
                        value = "Account Unlocked"
                    }
            )  # End Facts

	    }  # End Section

	    $ArrayTable.Add($Section)

    }  # End ForEach-Object

    $Body = ConvertTo-Json -Depth 8 @{
	    title = "Account Unlocked"
	    text  = "There are $($ArrayTable.Count) accounts locked out"
	    sections = $ArrayTable
        potentialAction =   @(
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
