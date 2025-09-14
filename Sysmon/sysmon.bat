@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem ----- Configuration -------------------------------------------------
set "XML=\\DomainControllerHostname\NETLOGON\Sysmon\sysmon-config.xml"
set "EXE=\\DomainControllerHostname\NETLOGON\Sysmon\Sysmon.exe"
set "LOG=%TEMP%\sysmon_deploy_%COMPUTERNAME%.log"

rem ----- Logging start -------------------------------------------------
(
    echo ==== %DATE% %TIME% ====
    echo Deploying Sysmon on %COMPUTERNAME%
) >"%LOG%"

rem ----- Install if missing -----------------------------------------
sc query Sysmon >nul 2>&1
if errorlevel 1060 (
    echo Installing Sysmon... >>"%LOG%"
    "%EXE%" -accepteula -i "%XML%" >>"%LOG%" 2>&1
    if errorlevel 1 (
        echo [!] Installation failed >>"%LOG%"
        goto :eof
    )
) else (
    echo Sysmon already installed >>"%LOG%"
)

rem ----- Start & verify ---------------------------------------------
net start Sysmon >nul 2>&1
if errorlevel 2 (
    echo Sysmon already running or start returned error 2 >>"%LOG%"
) else (
    sc query Sysmon | findstr /I "RUNNING" >nul
    if errorlevel 1 (
        echo [!] Sysmon not RUNNING after start >>"%LOG%"
    ) else (
        echo Sysmon is RUNNING >>"%LOG%"
    )
)

endlocal
