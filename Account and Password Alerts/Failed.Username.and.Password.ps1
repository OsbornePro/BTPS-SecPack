# This alert is used to alert IT when a failed password attempt occurs on a server
$Events = Get-WinEvent -LogName Security -FilterXPath '*[System[EventID=4625 and TimeCreated[timediff(@SystemTime) <= 120000]]]' -MaxEvents 1
$ArrayTable = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'

If ($Events) {

    $Events | ForEach-Object {

        $Section = @{
          activityTitle = "An account failed to log on"
          activitySubtitle = "$($_.Properties[5].Value)"
          activityText  = "Failed Login Attempt reported by $($_.MachineName) at $($_.TimeCreated)"
          activityImage = ""
	      facts		  = @(
                @{
                        name = "EventID: "
                        value = $_.Id
                    }
                @{
                        name = "User: "
                        value = $_.Properties[5].Value
                    },
                @{
                        name = "Device: "
                        value = $_.Properties[13].Value
                    },
                @{
                        name = "DC: "
                        value = $_.MachineName
                    },
                @{
                        name = "AuthType: "
                        value = $_.Properties[12].Value
                    },
                @{
                        name = "Date: "
                        value = $_.TimeCreated.ToString()
                    },
                @{
                        name = "Message"
                        value = "An account failed to log on"
                    }
            )  # End Facts

	    }  # End Section

	    $ArrayTable.Add($Section)

    }  # End ForEach-Object

    $Body = ConvertTo-Json -Depth 8 @{
	    title = "Failed Login Notification"
	    text  = "There are $($ArrayTable.Count) failed login attempts"
	    sections = $ArrayTable
        potentialAction =   @(
                        @{
                            '@context'  = 'http://schema.org'
                            '@type' = 'ViewAction'
                            name = 'How to Reset a User Password'
                            target = @("https://docs.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword?view=windowsserver2019-ps")
                        },
                        @{
                            '@context'  = 'http://schema.org'
                            '@type' = 'ViewAction'
                            name = 'Elastichsearch for Correlation Events'
                            target = @("SIEM TOOL LINK")
                        }
                    )  # End Potential Actions
    }  # End Body


    $WebhookUrl = 'WEBHOOK_URL_REPLACE'
    
    # Post the JSON Array Object to the Webhook Connector URI
    Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $Body -ContentType 'application/json'

}  # End If
