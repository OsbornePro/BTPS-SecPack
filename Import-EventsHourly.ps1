# Built off of some blog I read. https://blog.netnerds.net/2013/03/importing-windows-forwarded-events-into-sql-server-using-powershell/
#
# This should be configured to run in a task once an hour. This can be done by importing the XML file inside this repo

$XML = @'
<QueryList>
  <Query Id="0" Path="ForwardedEvents">
    <Select Path="ForwardedEvents">*[System[TimeCreated[timediff(@SystemTime) &lt;= 3900000]]]</Select>
  </Query>
</QueryList>
'@

$Events = Get-WinEvent -FilterXml $XML | Select-Object -Property ID,LevelDisplayName,LogName,MachineName,Message,ProviderName,RecordID,TaskDisplayName,TimeCreated -ErrorVariable $NoEventsError

If ($NoEventsError)
{

    Throw "[*] No new events to be imported"

}  # End If

$ConnectionString = 'Data Source="(local)";Integrated Security=true;Initial Catalog=EventCollections;'
$BulkCopy = New-Object -TypeName ("Data.SqlClient.SqlBulkCopy") $ConnectionString
$BulkCopy.DestinationTableName = "GeneralEvents"
$DT = New-Object -TypeName System.Data.DataTable

Write-Output "[*] Building the datatable"
$Columns = $Events | Select-Object -First 1 | Get-Member -MemberType NoteProperty | Select-Object -Expand Name
ForEach ($Column in $Columns)
{

    $Null = $DT.Columns.Add($Column)

}  # End ForEach

ForEach ($Event in $Events)
{

    $Row = $DT.NewRow()

    ForEach ($Column in $Columns)
    {

        $Row.Item($Column) = $Event.$Column

    }  # End ForEach

    $DT.Rows.Add($Row)

}  # End ForEach

Write-Output "[*] Writing to the database"

$BulkCopy.WriteToServer($DT)
