# This alert was meant to be used in cases where a user in your environment who should not have administrator credentials was given administrator credentials. It will alert you whenever their credentials are used to execute a process with higher privilege

$MonitorAdmin = ''

# If you did not use the install script you can execute the below commands to create a credential file. $Credential is used to send authenticated emails
#Get-Credential | Export-CliXml -Path "${env:\userprofile}\MonitorAdmin.Cred"
#$Credential = Import-CliXml -Path "${env:\userprofile}\MonitorAdmin.Cred"

Write-Verbose "Building queries"
$XMLConsent = "<QueryList>
    <Query Id='0' Path='Security'>
        <Select Path='Security'>
            *[System[(EventID=4648) and TimeCreated[timediff(@SystemTime) &lt;= 300000]] and EventData[Data[@Name='ProcessName']='C:\Windows\System32\consent.exe'] and EventData[Data[@Name='TargetUserName']=`'$MonitorAdmin`']]
        </Select>
    </Query>
</QueryList>"

$XMLAuthAsUser = "<QueryList>
    <Query Id='0' Path='Security'>
        <Select Path='Security'>
            *[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) &lt;= 300000]] and EventData[Data[@Name='LogonType']='11'] and EventData[Data[@Name='ProcessName']='C:\Windows\System32\consent.exe'] and EventData[Data[@Name='TargetUserName']=`'$MonitorAdmin`']]
        </Select>
    </Query>
</QueryList>"

$XMLProcInfo = "<QueryList>
    <Query Id='0' Path='Security'>
        <Select Path='Security'>
            *[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) &lt;= 300000]] and EventData[Data[@Name='TargetUserName']=`"$MonitorAdmin`"]]
        </Select>
    </Query>
</QueryList>"


If (Get-WinEvent -FilterXml $XMLConsent | Select-Object -Property * -First 1) {

    Write-Verbose "Admin credentials have been used to escalate privileges"

    Write-Verbose "Verifying password was entered correctly"
    If (Get-WinEvent -FilterXML $XMLAuthAsUser | Select-Object -Property * -First 1) {

        Write-Verbose "Administrator credentials were entered successfully"

        Write-Verbose "Correlating Process with successful logon"
        $ProcessInfo = Get-WinEvent -FilterXml $XMLProcInfo | Select-Object -Property * -First 1

        If ($ProcessInfo) {

            $Results = $ProcessInfo | ForEach-Object {

                $Obj = New-Object -TypeName PSObject | Select-Object -Property EventID, AdminUser, SID, MachineName, Process, Date, Message
                $Obj.EventID = $_.Id
                $Obj.AdminUser = $_.Properties[10].Value
                $Obj.SID = $_.Properties[9].Value
                $Obj.MachineName = $_.MachineName
                $Obj.Process = $_.Properties[5].Value
                $Obj.Date = $_.TimeCreated
                $Obj.Message = "A new process was started. It has been executed using verified Administrator credentials"

                $Obj

            }  # End ForEach-Object

            If ($Results) {

                $Admin = $Results.AdminUser
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

                $PreContent = "<Title>$Admin Used His Admin Credentials</Title>"
                $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
                $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
                $MailBody = $Results | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on the process that was created after $Admin executed it successfully using administrator credentials.<br><br><hr><br><br>" | Out-String

               Send-MailMessage -From FromEmail -To ToEmail -Subject "AD Event: $Admin Executed and Eleveated Process" -BodyAsHtml -Body "$MailBody" -SmtpServer UseSmtpServer -UseSsl -Port 587 -Credential $Credential

            }  # End If

        }  # End If

    }  # End If

}  # End If
