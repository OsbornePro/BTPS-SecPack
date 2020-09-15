$FinalResults= @()
$Date = Get-Date 
$ConnectionString = "Server=(localdb);Database=EventCollections;Integrated Security=True;Connect Timeout=30"

# SQL Queries to discover suspicious activity
$ClearedEventLog = "Id=1102"
$PasswordChange = "Id=4723 OR Id = 4724"
$UserAddedToAdminGroup = "Id=4732 OR Id=4756 OR Id=4728"
$UserRemovedFromAdminGroup = "Id=4733 OR Id=4757 OR Id=4729"
$UserAccountCreated = "Id=4720"
$UserAccountDeleted = "Id=4726"
$NewServiceInstalled = "Id=7045 AND Message NOT LIKE '%C:\ProgramData\Microsoft\Windows Defender\Definition Updates\%'"
$UserAccountLocked = "Id=4740"
$UserAccountUnlocked = "Id=4767"
$SpecialPrivilegeAssigned = "Id=4672 AND Message NOT LIKE '%paessler%' AND Message NOT LIKE '%dnsdynamic%' AND Message NOT LIKE '%nessus.admin%'"
$ReplayAttack = "Id=4649"

# This is an array of SQL Commands to execute
$Sqls = $ClearedEventLog,$PasswordChange,$UserAddedToAdminGroup,$UserRemovedFromAdminGroup,$UserAccountCreated,$UserAccountDeleted,$NewServiceInstalled,$UserAccountLocked,$UserAccountUnlocked,$SpecialPrivilegeAssigned,$ReplayAttack

Function Find-NewlyCreatedLocalAccounts {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$False,
                HelpMessage="Enter the connection string to connect to a SQL Server")]  # End Parameter
            [String]$ConnectionString, 
            
            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False,
                HelpMessage="Enter a MSSQL Query to execute")]  # End Parameter
            [String]$SqlCommand)  # End param

BEGIN 
{

    Write-Verbose "Creating connection to SQL database and SQL command"

    $Connection = New-Object -TypeName System.Data.SqlClient.SQLConnection($ConnectionString)
    $Connection.Open()

    $Command = New-Object -TypeName System.Data.SqlClient.SqlCommand($SqlCommand, $Connection)
    $Adapter = New-Object -TypeName System.Data.SqlClient.SqlDataAdapter -ArgumentList $Command
    $Dataset = New-Object -TypeName System.Data.DataSet

}  # End BEGIN
PROCESS
{

    Write-Verbose "Executing SQL Command: $SqlCommand"

    $Adapter.Fill($Dataset) | Out-Null
    $Connection.Close()

}  # End PROCESS
END
{

    $Dataset.Tables[0].Rows

}  # End END

}  # End Function Find-NewlyCreatedLocalAccounts


ForEach ($Sql in $Sqls)
{

    $SqlCommand = "DECLARE @CurHour DATETIME, @PrevHour DATETIME; SET @CurHour = DATEADD(hour, DATEDIFF(hour,'20110101',CURRENT_TIMESTAMP),'20110101'); SET @PrevHour = DATEADD(hour,-1, @CurHour); SELECT MachineName,TimeCreated,Id,Message FROM dbo.GeneralEvents WHERE TimeCreated >= @PrevHour and TimeCreated < @CurHour AND $Sql ORDER BY TimeCreated DESC"
    
    $Results = Find-NewlyCreatedLocalAccounts -ConnectionString $ConnectionString -SqlCommand $SqlCommand -Verbose  
    
    If ($Results) 
    {
        
        Switch ($Sql)
        {

            $ClearedEventLog {$Significance = 'Event Log Cleared'}
            $PasswordChange {$Significance = 'Password Change Attempt'}
            $UserAddedToAdminGroup {$Significance = 'User Added to Privileged Group'}
            $UserRemovedFromAdminGroup {$Significance = 'User Removed from Privileged Group'}
            $UserAccountCreated {$Significance = 'User Account Created'}
            $UserAccountDeleted {$Significance = 'User Account Deleted'}
            $NewServiceInstalled {$Significance = 'New Service Installed'}
            $UserAccountLocked {$Significance = 'Account Locked Out'}
            $UserAccountUnlocked {$Significance = 'Account Unlocked'}
            $SpecialPrivilegeAssigned {$Significance = 'Special Privileges Assigned'}
            $ReplayAttack {$Significance = 'Replay Attack Detected'}

        }  # End Switch

        $Results | Add-Member -NotePropertyName "Significance" -NotePropertyValue "$Significance"

        $FinalResults += $Results | Select-Object -Property TimeCreated,MachineName,Significance,Message,ID

        Remove-Variable Results,Significance

    }  # End If

}  # End ForEach

If ($FinalResults)
{

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
    $PreContent = "<Title>Suspicous Events</Title>"
    $NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
    $MailBody = $FinalResults | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains suspicous events that were triggered<br><br><hr><br><br>" | Out-String

    Send-MailMessage -From "alerts@osbornepro.com" -To "admin@osbornepro.com" -Subject "SUSPICIOUS EVENT TRIGGERED" -BodyAsHtml -Body "$MailBody" -SmtpServer mail.smtp2go.com 
    
}  # End If 
