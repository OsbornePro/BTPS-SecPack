if not exist "C:\Users\Public\Downloads\sysmon.xml" (
copy /z /y "\\DomainControllerHostname\NETLOGON\sysmon.xml" "C:\Users\Public\Downloads\sysmon.xml"
sysmon -c "C:\Users\Public\Downloads\sysmon.xml"
)
 
sc query "Sysmon" | Find "RUNNING"
If "%ERRORLEVEL%" EQU "1" (
goto startsysmon
)
:startsysmon
net start Sysmon
 
If "%ERRORLEVEL%" EQU "1" (
goto installsysmon
)
:installsysmon
"\\DomainControllerHostname\NETLOGON\sysmon.exe" /accepteula -i C:\Users\Public\Downloads\sysmon.xml