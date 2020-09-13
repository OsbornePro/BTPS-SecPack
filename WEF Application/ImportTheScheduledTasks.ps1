$BatchUser = Read-Host -Prompt "Enter a username who has 'Run As Batch Job' permissions. EXAMPLE: CONTOSO\BatchAdmin"

$Task1 = (Get-ChildItem -Path C:\ -Recurse -Filter 'TaskImportFile.xml' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
$Task2 = (Get-ChildItem -Path C:\ -Recurse -Filter 'TaskForSQLQueryEventsMonitor.xml' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName

Register-ScheduledTask -xml (Get-Content -Path $Task1 | Out-String) -TaskName "Import Events Into SQL Database" -TaskPath "\" -User $BatchUser –Force
Register-ScheduledTask -xml (Get-Content -Path $Task2 | Out-String) -TaskName "Query SQL Events for Indications of Compromise" -TaskPath "\" -User $BatchUser –Force
