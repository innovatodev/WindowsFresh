@echo off
:: https://privacy.sexy — v0.8.1 — Wed, 25 Nov 2020 05:01:34 GMT

:: ----------------------------------------------------------
:: -----------------Ensure admin privileges------------------
:: ----------------------------------------------------------
echo --- Ensure admin privileges
fltmc >nul 2>&1 || (
   echo Administrator privileges are required.
   PowerShell Start -Verb RunAs '%0' 2> nul || (
       echo Right-click on the script and select "Run as administrator".
       pause & exit 1
   )
   exit 0
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Clear credentials from Windows Credential Manager-----
:: ----------------------------------------------------------
echo --- Clear credentials from Windows Credential Manager
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\List.txt" /s /f /q
del "%TEMP%\tokensonly.txt" /s /f /q
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Delete controversial default0 user------------
:: ----------------------------------------------------------
echo --- Delete controversial default0 user
net user defaultuser0 /delete 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Empty trash bin----------------------
:: ----------------------------------------------------------
echo --- Empty trash bin
Powershell -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10);$bin.items() | ForEach { Write-Host "Deleting $($_.Name) from Recycle Bin"; Remove-Item $_.Path -Recurse -Force}"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Enable Reset Base in Dism Component Store---------
:: ----------------------------------------------------------
echo --- Enable Reset Base in Dism Component Store
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableResetbase" /t "REG_DWORD" /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Clear Windows Product Key from Registry----------
:: ----------------------------------------------------------
echo --- Clear Windows Product Key from Registry
slmgr /cpky
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Clear volume backups (shadow copies)-----------
:: ----------------------------------------------------------
echo --- Clear volume backups (shadow copies)
vssadmin delete shadows /all /quiet
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Remove Default Apps Associations-------------
:: ----------------------------------------------------------
echo --- Remove Default Apps Associations
dism /online /Remove-DefaultAppAssociations
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Clear (Reset) Network Data Usage-------------
:: ----------------------------------------------------------
echo --- Clear (Reset) Network Data Usage
setlocal EnableDelayedExpansion 
    SET /A dps_service_running=0
    SC queryex "DPS"|Find "STATE"|Find /v "RUNNING">Nul||(
        SET /A dps_service_running=1
        net stop DPS
    )
    del /F /S /Q /A "%windir%\System32\sru*"
    IF !dps_service_running! == 1 (
        net start DPS
    )
endlocal
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Clear Listary indexes-------------------
:: ----------------------------------------------------------
echo --- Clear Listary indexes
del /f /s /q %appdata%\Listary\UserData > nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Clear Java cache---------------------
:: ----------------------------------------------------------
echo --- Clear Java cache
rd /s /q "%APPDATA%\Sun\Java\Deployment\cache"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Clear Flash traces--------------------
:: ----------------------------------------------------------
echo --- Clear Flash traces
rd /s /q "%APPDATA%\Macromedia\Flash Player"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Clear Steam dumps, logs and traces------------
:: ----------------------------------------------------------
echo --- Clear Steam dumps, logs and traces
del /f /q %ProgramFiles(x86)%\Steam\Dumps
del /f /q %ProgramFiles(x86)%\Steam\Traces
del /f /q %ProgramFiles(x86)%\Steam\appcache\*.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Clear Visual Studio telemetry and feedback data------
:: ----------------------------------------------------------
echo --- Clear Visual Studio telemetry and feedback data
rmdir /s /q "%AppData%\vstelemetry" 2>nul
rmdir /s /q "%LocalAppData%\Microsoft\VSApplicationInsights" 2>nul
rmdir /s /q "%ProgramData%\Microsoft\VSApplicationInsights" 2>nul
rmdir /s /q "%Temp%\Microsoft\VSApplicationInsights" 2>nul
rmdir /s /q "%Temp%\VSFaultInfo" 2>nul
rmdir /s /q "%Temp%\VSFeedbackPerfWatsonData" 2>nul
rmdir /s /q "%Temp%\VSFeedbackVSRTCLogs" 2>nul
rmdir /s /q "%Temp%\VSRemoteControl" 2>nul
rmdir /s /q "%Temp%\VSTelem" 2>nul
rmdir /s /q "%Temp%\VSTelem.Out" 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Clear Dotnet CLI telemetry----------------
:: ----------------------------------------------------------
echo --- Clear Dotnet CLI telemetry
rmdir /s /q "%USERPROFILE%\.dotnet\TelemetryStorageService" 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Clear regedit last key------------------
:: ----------------------------------------------------------
echo --- Clear regedit last key
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Clear regedit favorites------------------
:: ----------------------------------------------------------
echo --- Clear regedit favorites
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Clear list of recent programs opened-----------
:: ----------------------------------------------------------
echo --- Clear list of recent programs opened
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Clear Adobe Media Browser MRU---------------
:: ----------------------------------------------------------
echo --- Clear Adobe Media Browser MRU
reg delete "HKCU\Software\Adobe\MediaBrowser\MRU" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Clear MSPaint MRU---------------------
:: ----------------------------------------------------------
echo --- Clear MSPaint MRU
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Clear Wordpad MRU---------------------
:: ----------------------------------------------------------
echo --- Clear Wordpad MRU
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Clear Map Network Drive MRU MRU--------------
:: ----------------------------------------------------------
echo --- Clear Map Network Drive MRU MRU
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Clear Windows Search Assistant history----------
:: ----------------------------------------------------------
echo --- Clear Windows Search Assistant history
reg delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Clear list of Recent Files Opened, by Filetype------
:: ----------------------------------------------------------
echo --- Clear list of Recent Files Opened, by Filetype
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Clear windows media player recent files and urls-----
:: ----------------------------------------------------------
echo --- Clear windows media player recent files and urls
reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Clear Most Recent Application's Use of DirectX------
:: ----------------------------------------------------------
echo --- Clear Most Recent Application's Use of DirectX
reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Direct3D\MostRecentApplication" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Clear Windows Run MRU & typedpaths------------
:: ----------------------------------------------------------
echo --- Clear Windows Run MRU & typedpaths
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Clear recently accessed files---------------
:: ----------------------------------------------------------
echo --- Clear recently accessed files
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Clear user pins----------------------
:: ----------------------------------------------------------
echo --- Clear user pins
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Clear Internet Explorer traces--------------
:: ----------------------------------------------------------
echo --- Clear Internet Explorer traces
del /f /q "%localappdata%\Microsoft\Windows\INetCache\IE\*"
reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLsTime" /va /f
rd /s /q "%localappdata%\Microsoft\Internet Explorer"
rd /s /q "%APPDATA%\Microsoft\Windows\Cookies"
rd /s /q "%USERPROFILE%\Cookies"
rd /s /q "%USERPROFILE%\Local Settings\Traces"
rd /s /q "%localappdata%\Temporary Internet Files"
rd /s /q "%localappdata%\Microsoft\Windows\Temporary Internet Files"
rd /s /q "%localappdata%\Microsoft\Windows\INetCookies\PrivacIE"
rd /s /q "%localappdata%\Microsoft\Feeds Cache"
rd /s /q "%localappdata%\Microsoft\InternetExplorer\DOMStore"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Clear Google Chrome traces----------------
:: ----------------------------------------------------------
echo --- Clear Google Chrome traces
del /f /q "%localappdata%\Google\Software Reporter Tool\*.log"
rd /s /q "%USERPROFILE%\Local Settings\Application Data\Google\Chrome\User Data"
rd /s /q "%localappdata%\Google\Chrome\User Data"
rd /s /q "%localappdata%\Google\CrashReports\""
rd /s /q "%localappdata%\Google\Chrome\User Data\Crashpad\reports\""
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Clear Opera traces--------------------
:: ----------------------------------------------------------
echo --- Clear Opera traces
rd /s /q "%USERPROFILE%\AppData\Local\Opera\Opera"
rd /s /q "%APPDATA%\Opera\Opera"
rd /s /q "%USERPROFILE%\Local Settings\Application Data\Opera\Opera"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Clear Safari traces--------------------
:: ----------------------------------------------------------
echo --- Clear Safari traces
rd /s /q "%USERPROFILE%\AppData\Local\Apple Computer\Safari\Traces"
rd /s /q "%APPDATA%\Apple Computer\Safari"
del /q /s /f "%USERPROFILE%\AppData\Local\Apple Computer\Safari\Cache.db"
del /q /s /f "%USERPROFILE%\AppData\Local\Apple Computer\Safari\WebpageIcons.db"
rd /s /q "%USERPROFILE%\Local Settings\Application Data\Apple Computer\Safari\Traces"
del /q /s /f "%USERPROFILE%\Local Settings\Application Data\Apple Computer\Safari\Cache.db"
del /q /s /f "%USERPROFILE%\Local Settings\Application Data\Safari\WebpageIcons.db"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Clear browsing history and caches-------------
:: ----------------------------------------------------------
echo --- Clear browsing history and caches
set ignoreFiles="content-prefs.sqlite" "permissions.sqlite" "favicons.sqlite"
for %%d in ("%APPDATA%\Mozilla\Firefox\Profiles\"
            "%USERPROFILE%\Local Settings\Application Data\Mozilla\Firefox\Profiles\"
        ) do (
    IF EXIST %%d (
        FOR /d %%p IN (%%d*) DO (
            for /f "delims=" %%f in ('dir /b /s "%%p\*.sqlite" 2^>nul') do (
                set "continue="
                for %%i in (%ignoreFiles%) do ( 
                    if %%i == "%%~nxf" (
                        set continue=1
                    )
                )
                if not defined continue (
                    del /q /s /f %%f
                )
            )
        )
    )
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Clear all Firefox user profiles, settings and data----
:: ----------------------------------------------------------
echo --- Clear all Firefox user profiles, settings and data
rd /s /q "%LOCALAPPDATA%\Mozilla\Firefox\Profiles"
rd /s /q "%APPDATA%\Mozilla\Firefox\Profiles"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Clear thumbnail cache-------------------
:: ----------------------------------------------------------
echo --- Clear thumbnail cache
del /f /s /q /a %LocalAppData%\Microsoft\Windows\Explorer\*.db
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Clear Windows temp files-----------------
:: ----------------------------------------------------------
echo --- Clear Windows temp files
del /f /q %localappdata%\Temp\*
rd /s /q "%WINDIR%\Temp"
rd /s /q "%TEMP%"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Clear main telemetry file-----------------
:: ----------------------------------------------------------
echo --- Clear main telemetry file
if exist "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" (
    takeown /f "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r /d y
    icacls "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
    echo "" > "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    echo Clear successful: "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
) else (
    echo "Main telemetry file does not exist. Good!"
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Clear Event Logs in Event Viewer-------------
:: ----------------------------------------------------------
echo --- Clear Event Logs in Event Viewer
REM https://social.technet.microsoft.com/Forums/en-US/f6788f7d-7d04-41f1-a64e-3af9f700e4bd/failed-to-clear-log-microsoftwindowsliveidoperational-access-is-denied?forum=win10itprogeneral
wevtutil sl Microsoft-Windows-LiveId/Operational /ca:O:BAG:SYD:(A;;0x1;;;SY)(A;;0x5;;;BA)(A;;0x1;;;LA)
for /f "tokens=*" %%i in ('wevtutil.exe el') DO (
    echo Deleting event log: "%%i"
    wevtutil.exe cl %1 "%%i"
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Clear Optional Component Manager and COM+ components logs-
:: ----------------------------------------------------------
echo --- Clear Optional Component Manager and COM+ components logs
del /f /q %SystemRoot%\comsetup.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Clear Distributed Transaction Coordinator logs------
:: ----------------------------------------------------------
echo --- Clear Distributed Transaction Coordinator logs
del /f /q %SystemRoot%\DtcInstall.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Clear Pending File Rename Operations logs---------
:: ----------------------------------------------------------
echo --- Clear Pending File Rename Operations logs
del /f /q %SystemRoot%\PFRO.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Clear Windows Deployment Upgrade Process Logs-------
:: ----------------------------------------------------------
echo --- Clear Windows Deployment Upgrade Process Logs
del /f /q %SystemRoot%\setupact.log
del /f /q %SystemRoot%\setuperr.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Clear Windows Setup Logs-----------------
:: ----------------------------------------------------------
echo --- Clear Windows Setup Logs
del /f /q %SystemRoot%\setupapi.log
del /f /q %SystemRoot%\Panther\*
del /f /q %SystemRoot%\inf\setupapi.app.log
del /f /q %SystemRoot%\inf\setupapi.dev.log
del /f /q %SystemRoot%\inf\setupapi.offline.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Clear Windows System Assessment Tool logs---------
:: ----------------------------------------------------------
echo --- Clear Windows System Assessment Tool logs
del /f /q %SystemRoot%\Performance\WinSAT\winsat.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Clear Password change events---------------
:: ----------------------------------------------------------
echo --- Clear Password change events
del /f /q %SystemRoot%\debug\PASSWD.LOG
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Clear user web cache database---------------
:: ----------------------------------------------------------
echo --- Clear user web cache database
del /f /q %localappdata%\Microsoft\Windows\WebCache\*.*
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Clear system temp folder when noone is logged in-----
:: ----------------------------------------------------------
echo --- Clear system temp folder when noone is logged in
del /f /q %SystemRoot%\ServiceProfiles\LocalService\AppData\Local\Temp\*.*
:: ----------------------------------------------------------


:: Clear DISM (Deployment Image Servicing and Management) Logs
echo --- Clear DISM (Deployment Image Servicing and Management) Logs
del /f /q  %SystemRoot%\Logs\CBS\CBS.log
del /f /q  %SystemRoot%\Logs\DISM\DISM.log
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Clear WUAgent (Windows Update History) logs--------
:: ----------------------------------------------------------
echo --- Clear WUAgent (Windows Update History) logs
setlocal EnableDelayedExpansion 
    SET /A wuau_service_running=0
    SC queryex "wuauserv"|Find "STATE"|Find /v "RUNNING">Nul||(
        SET /A wuau_service_running=1
        net stop wuauserv
    )
    del /q /s /f "%SystemRoot%\SoftwareDistribution"
    IF !wuau_service_running! == 1 (
        net start wuauserv
    )
endlocal
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Clear Server-initiated Healing Events Logs--------
:: ----------------------------------------------------------
echo --- Clear Server-initiated Healing Events Logs
del /f /q "%SystemRoot%\Logs\SIH\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Common Language Runtime Logs---------------
:: ----------------------------------------------------------
echo --- Common Language Runtime Logs
del /f /q "%LocalAppData%\Microsoft\CLR_v4.0\UsageTraces\*"
del /f /q "%LocalAppData%\Microsoft\CLR_v4.0_32\UsageTraces\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Network Setup Service Events Logs-------------
:: ----------------------------------------------------------
echo --- Network Setup Service Events Logs
del /f /q "%SystemRoot%\Logs\NetSetup\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disk Cleanup tool (Cleanmgr.exe) Logs-----------
:: ----------------------------------------------------------
echo --- Disk Cleanup tool (Cleanmgr.exe) Logs
del /f /q "%SystemRoot%\System32\LogFiles\setupcln\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Clear Windows update and SFC scan logs----------
:: ----------------------------------------------------------
echo --- Clear Windows update and SFC scan logs
del /f /q %SystemRoot%\Temp\CBS\*
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Clear Windows Update Medic Service logs----------
:: ----------------------------------------------------------
echo --- Clear Windows Update Medic Service logs
takeown /f %SystemRoot%\Logs\waasmedic /r /d y
icacls %SystemRoot%\Logs\waasmedic /grant administrators:F /t
rd /s /q %SystemRoot%\Logs\waasmedic
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Clear Cryptographic Services Traces------------
:: ----------------------------------------------------------
echo --- Clear Cryptographic Services Traces
del /f /q %SystemRoot%\System32\catroot2\dberr.txt
del /f /q %SystemRoot%\System32\catroot2.log
del /f /q %SystemRoot%\System32\catroot2.jrs
del /f /q %SystemRoot%\System32\catroot2.edb
del /f /q %SystemRoot%\System32\catroot2.chk
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Windows Update Events Logs----------------
:: ----------------------------------------------------------
echo --- Windows Update Events Logs
del /f /q "%SystemRoot%\Logs\SIH\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Windows Update Logs--------------------
:: ----------------------------------------------------------
echo --- Windows Update Logs
del /f /q "%SystemRoot%\Traces\WindowsUpdate\*"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable cloud speech recognation-------------
:: ----------------------------------------------------------
echo --- Disable cloud speech recognation
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t "REG_DWORD" /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Disable active prompting (pings to MSFT NCSI server)---
:: ----------------------------------------------------------
echo --- Disable active prompting (pings to MSFT NCSI server)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Opt out from Windows privacy consent-----------
:: ----------------------------------------------------------
echo --- Opt out from Windows privacy consent
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable Windows feedback-----------------
:: ----------------------------------------------------------
echo --- Disable Windows feedback
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f 
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable text and handwriting collection----------
:: ----------------------------------------------------------
echo --- Disable text and handwriting collection
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Turn off sensors---------------------
:: ----------------------------------------------------------
echo --- Turn off sensors
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable Wi-Fi sense--------------------
:: ----------------------------------------------------------
echo --- Disable Wi-Fi sense
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable App Launch Tracking----------------
:: ----------------------------------------------------------
echo --- Disable App Launch Tracking
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /d 0 /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Inventory Collector----------------
:: ----------------------------------------------------------
echo --- Disable Inventory Collector
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Website Access of Language List----------
:: ----------------------------------------------------------
echo --- Disable Website Access of Language List
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Auto Downloading Maps---------------
:: ----------------------------------------------------------
echo --- Disable Auto Downloading Maps
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable steps recorder------------------
:: ----------------------------------------------------------
echo --- Disable steps recorder
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable game screen recording---------------
:: ----------------------------------------------------------
echo --- Disable game screen recording
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Windows DRM internet access------------
:: ----------------------------------------------------------
echo --- Disable Windows DRM internet access
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable feedback on write (sending typing info)------
:: ----------------------------------------------------------
echo --- Disable feedback on write (sending typing info)
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable Activity Feed-------------------
:: ----------------------------------------------------------
echo --- Disable Activity Feed
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable Customer Experience Improvement (CEIP/SQM)----
:: ----------------------------------------------------------
echo --- Disable Customer Experience Improvement (CEIP/SQM)
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Application Impact Telemetry (AIT)--------
:: ----------------------------------------------------------
echo --- Disable Application Impact Telemetry (AIT)
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable diagnostics telemetry---------------
:: ----------------------------------------------------------
echo --- Disable diagnostics telemetry
reg add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d 4 /f
sc stop "DiagTrack" & sc config "DiagTrack" start=disabled
sc stop "dmwappushservice" & sc config "dmwappushservice" start=disabled
sc stop "diagnosticshub.standardcollector.service" & sc config "diagnosticshub.standardcollector.service" start=disabled
sc stop "diagsvc" & sc config "diagsvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Customer Experience Improvement Program------
:: ----------------------------------------------------------
echo --- Disable Customer Experience Improvement Program
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Webcam Telemetry (devicecensus.exe)--------
:: ----------------------------------------------------------
echo --- Disable Webcam Telemetry (devicecensus.exe)
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable Application Experience (Compatibility Telemetry)-
:: ----------------------------------------------------------
echo --- Disable Application Experience (Compatibility Telemetry)
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /DISABLE
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable telemetry in data collection policy--------
:: ----------------------------------------------------------
echo --- Disable telemetry in data collection policy
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /d 0 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable license telemetry-----------------
:: ----------------------------------------------------------
echo --- Disable license telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable error reporting------------------
:: ----------------------------------------------------------
echo --- Disable error reporting
:: Disable Windows Error Reporting (WER)
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f
:: DefaultConsent / 1 - Always ask (default) / 2 - Parameters only / 3 - Parameters and safe data / 4 - All data
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
:: Disable WER sending second-level data
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
:: Disable WER crash dialogs, popups
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
:: Disable Windows Error Reporting Service
sc stop "WerSvc" & sc config "WerSvc" start=disabled
sc stop "wercplsupport" & sc config "wercplsupport" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable device metadata retrieval (breaks auto updates)--
:: ----------------------------------------------------------
echo --- Disable device metadata retrieval (breaks auto updates)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Do not include drivers with Windows Updates--------
:: ----------------------------------------------------------
echo --- Do not include drivers with Windows Updates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Prevent Windows Update for device driver search------
:: ----------------------------------------------------------
echo --- Prevent Windows Update for device driver search
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Deny app access to location----------------
:: ----------------------------------------------------------
echo --- Deny app access to location
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /d "Deny" /f
:: For older Windows (before 1903)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /d "0" /t REG_DWORD /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Deny app accesss to account info, name and picture----
:: ----------------------------------------------------------
echo --- Deny app accesss to account info, name and picture
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /d "Deny" /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Deny app access to motion data--------------
:: ----------------------------------------------------------
echo --- Deny app access to motion data
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Deny app access to phone-----------------
:: ----------------------------------------------------------
echo --- Deny app access to phone
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Deny app access to trusted devices------------
:: ----------------------------------------------------------
echo --- Deny app access to trusted devices
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Deny app sync with devices (unpaired, beacons, TVs etc.)-
:: ----------------------------------------------------------
echo --- Deny app sync with devices (unpaired, beacons, TVs etc.)
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Deny app access to camera-----------------
:: ----------------------------------------------------------
echo --- Deny app access to camera
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Deny app access to microphone---------------
:: ----------------------------------------------------------
echo --- Deny app access to microphone
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: Deny apps share and sync non-explicitly paired wireless devices over uPnP
echo --- Deny apps share and sync non-explicitly paired wireless devices over uPnP
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /t REG_SZ /v "Value" /d "Deny" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Deny app access to diagnostics info about your other apps-
:: ----------------------------------------------------------
echo --- Deny app access to diagnostics info about your other apps
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /d "Deny" /t REG_SZ /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Deny app access to your contacts-------------
:: ----------------------------------------------------------
echo --- Deny app access to your contacts
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Deny app access to Notifications-------------
:: ----------------------------------------------------------
echo --- Deny app access to Notifications
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Deny app access to Calendar----------------
:: ----------------------------------------------------------
echo --- Deny app access to Calendar
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Deny app access to call history--------------
:: ----------------------------------------------------------
echo --- Deny app access to call history
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Deny app access to email-----------------
:: ----------------------------------------------------------
echo --- Deny app access to email
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /t REG_SZ /v "Value" /d DENY /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Deny app access to tasks-----------------
:: ----------------------------------------------------------
echo --- Deny app access to tasks
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /d "Deny" /t REG_SZ /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Deny app access to messaging (SMS / MMS)---------
:: ----------------------------------------------------------
echo --- Deny app access to messaging (SMS / MMS)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /t REG_SZ /v "Value" /d "Deny" /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Deny app access to radios-----------------
:: ----------------------------------------------------------
echo --- Deny app access to radios
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /d "Deny" /t REG_SZ /f
:: For older Windows (before 1903)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /t REG_SZ /v "Value" /d DENY /f
:: Using GPO (re-activation through GUI is not possible)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_ForceDenyTheseApps" /t REG_MULTI_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Deny app access to bluetooth devices-----------
:: ----------------------------------------------------------
echo --- Deny app access to bluetooth devices
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Deny app access to Document folder------------
:: ----------------------------------------------------------
echo --- Deny app access to Document folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Deny app access to Pictures folder------------
:: ----------------------------------------------------------
echo --- Deny app access to Pictures folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Deny app access to Videos folder-------------
:: ----------------------------------------------------------
echo --- Deny app access to Videos folder
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Deny app access to other filesystem------------
:: ----------------------------------------------------------
echo --- Deny app access to other filesystem
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /d "Deny" /t REG_SZ /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Turn off Windows Location Provider------------
:: ----------------------------------------------------------
echo --- Turn off Windows Location Provider
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Turn off location scripting----------------
:: ----------------------------------------------------------
echo --- Turn off location scripting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Turn off location---------------------
:: ----------------------------------------------------------
echo --- Turn off location
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /d "1" /t REG_DWORD /f
:: For older Windows (before 1903)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable cortana----------------------
:: ----------------------------------------------------------
echo --- Disable cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent"  /d 0 /t REG_DWORD /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable web search in search bar-------------
:: ----------------------------------------------------------
echo --- Disable web search in search bar
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /d 0 /t REG_DWORD /f                   
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable search web when searching pc-----------
:: ----------------------------------------------------------
echo --- Disable search web when searching pc
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable search indexing encrypted items / stores-----
:: ----------------------------------------------------------
echo --- Disable search indexing encrypted items / stores
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowIndexingEncryptedStoresOrItems /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable location based info in searches----------
:: ----------------------------------------------------------
echo --- Disable location based info in searches
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable language detection----------------
:: ----------------------------------------------------------
echo --- Disable language detection
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AlwaysUseAutoLangDetection /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable ad customization with Advertising ID-------
:: ----------------------------------------------------------
echo --- Disable ad customization with Advertising ID
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable targeted tips-------------------
:: ----------------------------------------------------------
echo --- Disable targeted tips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn Off Suggested Content in Settings app--------
:: ----------------------------------------------------------
echo --- Turn Off Suggested Content in Settings app
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Do not allow the use of biometrics------------
:: ----------------------------------------------------------
echo --- Do not allow the use of biometrics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Do not allow users to log on using biometrics-------
:: ----------------------------------------------------------
echo --- Do not allow users to log on using biometrics
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Do not start Windows Biometric Service----------
:: ----------------------------------------------------------
echo --- Do not start Windows Biometric Service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d 4 /f
sc stop "WbioSrvc" & sc config "WbioSrvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Windows Insider Service--------------
:: ----------------------------------------------------------
echo --- Disable Windows Insider Service
sc stop "wisvc" & sc config "wisvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Do not let Microsoft try features on this build------
:: ----------------------------------------------------------
echo --- Do not let Microsoft try features on this build
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t "REG_DWORD" /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable getting preview builds of Windows---------
:: ----------------------------------------------------------
echo --- Disable getting preview builds of Windows
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Remove "Windows Insider Program" from Settings------
:: ----------------------------------------------------------
echo --- Remove "Windows Insider Program" from Settings
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t "REG_DWORD" /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable all settings sync-----------------
:: ----------------------------------------------------------
echo --- Disable all settings sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Application Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Application Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable App Sync Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable App Sync Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Credentials Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Credentials Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Desktop Theme Setting Sync------------
:: ----------------------------------------------------------
echo --- Disable Desktop Theme Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Personalization Setting Sync-----------
:: ----------------------------------------------------------
echo --- Disable Personalization Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Start Layout Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Start Layout Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Web Browser Setting Sync-------------
:: ----------------------------------------------------------
echo --- Disable Web Browser Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable Windows Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable Windows Setting Sync
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Language Setting Sync---------------
:: ----------------------------------------------------------
echo --- Disable Language Setting Sync
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /t REG_DWORD /v "Enabled" /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable NET Core CLI telemetry--------------
:: ----------------------------------------------------------
echo --- Disable NET Core CLI telemetry
setx DOTNET_CLI_TELEMETRY_OPTOUT 1
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable PowerShell 7+ telemetry--------------
:: ----------------------------------------------------------
echo --- Disable PowerShell 7+ telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Google update service---------------
:: ----------------------------------------------------------
echo --- Disable Google update service
sc stop "gupdate" & sc config "gupdate" start=disabled
sc stop "gupdatem" & sc config "gupdatem" start=disabled
schtasks /change /disable /tn "GoogleUpdateTaskMachineCore"
schtasks /change /disable /tn "GoogleUpdateTaskMachineUA"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Adobe Acrobat update service-----------
:: ----------------------------------------------------------
echo --- Disable Adobe Acrobat update service
sc stop "AdobeARMservice" & sc config "AdobeARMservice" start=disabled
sc stop "adobeupdateservice" & sc config "adobeupdateservice" start=disabled
sc stop "adobeflashplayerupdatesvc" & sc config "adobeflashplayerupdatesvc" start=disabled
schtasks /change /tn "Adobe Acrobat Update Task" /disable
schtasks /change /tn "Adobe Flash Player Updater" /disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Razer Game Scanner Service------------
:: ----------------------------------------------------------
echo --- Disable Razer Game Scanner Service
sc stop "Razer Game Scanner Service" & sc config "Razer Game Scanner Service" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Logitech Gaming Registry Service---------
:: ----------------------------------------------------------
echo --- Disable Logitech Gaming Registry Service
sc stop "LogiRegistryService" & sc config "LogiRegistryService" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Dropbox auto update service------------
:: ----------------------------------------------------------
echo --- Disable Dropbox auto update service
sc stop "dbupdate" & sc config "dbupdate" start=disabled
sc stop "dbupdatem" & sc config "dbupdatem" start=disabled
schtasks /Change /DISABLE /TN "DropboxUpdateTaskMachineCore"
schtasks /Change /DISABLE /TN "DropboxUpdateTaskMachineUA" 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable CCleaner Monitoring----------------
:: ----------------------------------------------------------
echo --- Disable CCleaner Monitoring
reg add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)HealthCheck" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickClean" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickCleanIpm" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable visual studio telemetry--------------
:: ----------------------------------------------------------
echo --- Disable visual studio telemetry
reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Visual Studio feedback--------------
:: ----------------------------------------------------------
echo --- Disable Visual Studio feedback
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Stop and disable Visual Studio Standard Collector Service-
:: ----------------------------------------------------------
echo --- Stop and disable Visual Studio Standard Collector Service
sc stop "VSStandardCollectorService150" & sc config "VSStandardCollectorService150" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Disable SQM OS key--------------------
:: ----------------------------------------------------------
echo --- Disable SQM OS key
if %PROCESSOR_ARCHITECTURE%==x86 ( REM is 32 bit?
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
) else (
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable SQM group policy-----------------
:: ----------------------------------------------------------
echo --- Disable SQM group policy
reg add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Do not send Watson events-----------------
:: ----------------------------------------------------------
echo --- Do not send Watson events
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericReports" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable Malicious Software Reporting tool diagnostic data-
:: ----------------------------------------------------------
echo --- Disable Malicious Software Reporting tool diagnostic data
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable local setting override for reporting to Microsoft MAPS
echo --- Disable local setting override for reporting to Microsoft MAPS
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn off Windows Defender SpyNet reporting--------
:: ----------------------------------------------------------
echo --- Turn off Windows Defender SpyNet reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Do not send file samples for further analysis-------
:: ----------------------------------------------------------
echo --- Do not send file samples for further analysis
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Uninstall NVIDIA telemetry tasks-------------
:: ----------------------------------------------------------
echo --- Uninstall NVIDIA telemetry tasks
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Delete NVIDIA residual telemetry files----------
:: ----------------------------------------------------------
echo --- Delete NVIDIA residual telemetry files
del /s %systemdrive%\System32\DriverStore\FileRepository\NvTelemetry*.dll
rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\NvTelemetry" 2>nul
rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\NvTelemetry" 2>nul
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Opt out from NVIDIA telemetry---------------
:: ----------------------------------------------------------
echo --- Opt out from NVIDIA telemetry
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" /v "Start" /t REG_DWORD /d 4 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable NVIDIA telemetry services-------------
:: ----------------------------------------------------------
echo --- Disable NVIDIA telemetry services
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Visual Studio Code telemetry-----------
:: ----------------------------------------------------------
echo --- Disable Visual Studio Code telemetry
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'telemetry.enableTelemetry' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Visual Studio Code crash reporting--------
:: ----------------------------------------------------------
echo --- Disable Visual Studio Code crash reporting
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'telemetry.enableCrashReporter' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Do not run Microsoft online experiments----------
:: ----------------------------------------------------------
echo --- Do not run Microsoft online experiments
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'workbench.enableExperiments' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Choose manual updates over automatic updates-------
:: ----------------------------------------------------------
echo --- Choose manual updates over automatic updates
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'update.mode' -Value \"manual\" -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: Show Release Notes from Microsoft online service after an update
echo --- Show Release Notes from Microsoft online service after an update
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'update.showReleaseNotes' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: Automatically check extensions from Microsoft online service
echo --- Automatically check extensions from Microsoft online service
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'extensions.autoCheckUpdates' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Fetch recommendations from a Microsoft online service---
:: ----------------------------------------------------------
echo --- Fetch recommendations from a Microsoft online service
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'extensions.showRecommendationsOnlyOnDemand' -Value $true -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Automatically fetch git commits from remote repository--
:: ----------------------------------------------------------
echo --- Automatically fetch git commits from remote repository
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'git.autofetch' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Fetch package information from NPM and Bower-------
:: ----------------------------------------------------------
echo --- Fetch package information from NPM and Bower
Powershell -Command "$jsonfile = \"$env:APPDATA\Code\User\settings.json\"; $json = Get-Content $jsonfile | Out-String | ConvertFrom-Json; $json | Add-Member -Type NoteProperty -Name 'npm.fetchOnlinePackageInfo' -Value $false -Force; $json | ConvertTo-Json | Set-Content $jsonfile;"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Microsoft Office logging-------------
:: ----------------------------------------------------------
echo --- Disable Microsoft Office logging
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable client telemetry-----------------
:: ----------------------------------------------------------
echo --- Disable client telemetry
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Customer Experience Improvement Program----------
:: ----------------------------------------------------------
echo --- Customer Experience Improvement Program
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable feedback---------------------
:: ----------------------------------------------------------
echo --- Disable feedback
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Disable telemetry agent------------------
:: ----------------------------------------------------------
echo --- Disable telemetry agent
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Subscription Heartbeat--------------
:: ----------------------------------------------------------
echo --- Disable Subscription Heartbeat
schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE
schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable live tile data collection-------------
:: ----------------------------------------------------------
echo --- Disable live tile data collection
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable MFU tracking-------------------
:: ----------------------------------------------------------
echo --- Disable MFU tracking
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable recent apps--------------------
:: ----------------------------------------------------------
echo --- Disable recent apps
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableRecentApps" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Turn off backtracking-------------------
:: ----------------------------------------------------------
echo --- Turn off backtracking
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "TurnOffBackstack" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Search Suggestions in Edge------------
:: ----------------------------------------------------------
echo --- Disable Search Suggestions in Edge
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable Automatic Installation of Microsoft Edge Chromium-
:: ----------------------------------------------------------
echo --- Disable Automatic Installation of Microsoft Edge Chromium
reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable Geolocation in Internet Explorer---------
:: ----------------------------------------------------------
echo --- Disable Geolocation in Internet Explorer
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Internet Explorer InPrivate logging--------
:: ----------------------------------------------------------
echo --- Disable Internet Explorer InPrivate logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" /v "DisableLogging" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable Internet Explorer CEIP--------------
:: ----------------------------------------------------------
echo --- Disable Internet Explorer CEIP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable calling legacy WCM policies------------
:: ----------------------------------------------------------
echo --- Disable calling legacy WCM policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CallLegacyWCMPolicies" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Disable SSLv3 fallback------------------
:: ----------------------------------------------------------
echo --- Disable SSLv3 fallback
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableSSL3Fallback" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable ignoring cert errors---------------
:: ----------------------------------------------------------
echo --- Disable ignoring cert errors
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PreventIgnoreCertErrors" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Chrome Software Reporter Tool-----------
:: ----------------------------------------------------------
echo --- Disable Chrome Software Reporter Tool
icacls "%localappdata%\Google\Chrome\User Data\SwReporter" /inheritance:r /deny "*S-1-1-0:(OI)(CI)(F)" "*S-1-5-7:(OI)(CI)(F)"
cacls "%localappdata%\Google\Chrome\User Data\SwReporter" /e /c /d %username%
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "1" /t REG_SZ /d "software_reporter_tool.exe" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Chrome metrics reporting-------------
:: ----------------------------------------------------------
echo --- Disable Chrome metrics reporting
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Do not share share scanned software data to Google----
:: ----------------------------------------------------------
echo --- Do not share share scanned software data to Google
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Prevent Chrome from scanning the system for cleanup----
:: ----------------------------------------------------------
echo --- Prevent Chrome from scanning the system for cleanup
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable Firefox metrics reporting-------------
:: ----------------------------------------------------------
echo --- Disable Firefox metrics reporting
reg add HKLM\SOFTWARE\Policies\Mozilla\Firefox /v DisableTelemetry /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable default browser agent reporting policy------
:: ----------------------------------------------------------
echo --- Disable default browser agent reporting policy
reg add HKLM\SOFTWARE\Policies\Mozilla\Firefox /v DisableDefaultBrowserAgent /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable default browser agent reporting services-----
:: ----------------------------------------------------------
echo --- Disable default browser agent reporting services
schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB"
schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent D2CEEC440E2074BD"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Do not send Windows Media Player statistics--------
:: ----------------------------------------------------------
echo --- Do not send Windows Media Player statistics
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable metadata retrieval----------------
:: ----------------------------------------------------------
echo --- Disable metadata retrieval
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable dows Media Player Network Sharing Service-----
:: ----------------------------------------------------------
echo --- Disable dows Media Player Network Sharing Service
sc stop "WMPNetworkSvc" & sc config "WMPNetworkSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable administrative shares---------------
:: ----------------------------------------------------------
echo --- Disable administrative shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Force enable data execution prevention (DEP)-------
:: ----------------------------------------------------------
echo --- Force enable data execution prevention (DEP)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable AutoPlay and AutoRun---------------
:: ----------------------------------------------------------
echo --- Disable AutoPlay and AutoRun
:: 255 (0xff) means all drives
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable remote Assistance-----------------
:: ----------------------------------------------------------
echo --- Disable remote Assistance
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable lock screen camera----------------
:: ----------------------------------------------------------
echo --- Disable lock screen camera
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Prevent the storage of the LAN Manager hash of passwords-
:: ----------------------------------------------------------
echo --- Prevent the storage of the LAN Manager hash of passwords
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "NoLMHash" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable Windows Installer Always install with elevated privileges
echo --- Disable Windows Installer Always install with elevated privileges
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Prevent WinRM from using Basic Authentication-------
:: ----------------------------------------------------------
echo --- Prevent WinRM from using Basic Authentication
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowBasic" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Restrict anonymous enumeration of shares---------
:: ----------------------------------------------------------
echo --- Restrict anonymous enumeration of shares
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Refuse less secure authentication-------------
:: ----------------------------------------------------------
echo --- Refuse less secure authentication
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LmCompatibilityLevel" /t REG_DWORD /d 5 /f
:: ----------------------------------------------------------


:: Enable Structured Exception Handling Overwrite Protection (SEHOP)
echo --- Enable Structured Exception Handling Overwrite Protection (SEHOP)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Block Anonymous enumeration of SAM accounts--------
:: ----------------------------------------------------------
echo --- Block Anonymous enumeration of SAM accounts
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Restrict anonymous access to Named Pipes and Shares----
:: ----------------------------------------------------------
echo --- Restrict anonymous access to Named Pipes and Shares
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable the Windows Connect Now wizard----------
:: ----------------------------------------------------------
echo --- Disable the Windows Connect Now wizard
reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\UI" /v "DisableWcnUi" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableFlashConfigRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableInBand802DOT11Registrar" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableUPnPRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableWPDRegistrar" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "EnableRegistrars" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Spectre variant 2 and meltdown (own OS)----------
:: ----------------------------------------------------------
echo --- Spectre variant 2 and meltdown (own OS)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
wmic cpu get name | findstr "Intel" >nul && (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 0 /f
)
wmic cpu get name | findstr "AMD" >nul && (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 64 /f
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Spectre variant 2 and meltdown (HyperV)----------
:: ----------------------------------------------------------
echo --- Spectre variant 2 and meltdown (HyperV)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization" /v MinVmVersionForCpuBasedMitigations /t REG_SZ /d "1.0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable unsafe SMBv1 protocol---------------
:: ----------------------------------------------------------
echo --- Disable unsafe SMBv1 protocol
dism /online /Disable-Feature /FeatureName:"SMB1Protocol" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Client" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Server" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable PowerShell 2.0 against downgrade attacks-----
:: ----------------------------------------------------------
echo --- Disable PowerShell 2.0 against downgrade attacks
dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /NoRestart
dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Increase Diffie-Hellman key (DHK) exchange to 4096-bit--
:: ----------------------------------------------------------
echo --- Increase Diffie-Hellman key (DHK) exchange to 4096-bit
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /f /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /f /v ClientMinKeyBitLength /t REG_DWORD /d 0x00001000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /f /v Enabled /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Disable RC2 cipher--------------------
:: ----------------------------------------------------------
echo --- Disable RC2 cipher
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" /f /v Enabled /t REG_DWORD /d 0x00000000
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Disable RC4 cipher--------------------
:: ----------------------------------------------------------
echo --- Disable RC4 cipher
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /f /v Enabled /t REG_DWORD /d 0x00000000
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Disable DES cipher--------------------
:: ----------------------------------------------------------
echo --- Disable DES cipher
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /f /v Enabled /t REG_DWORD /d 0x00000000
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable 3DES (Triple DES) cipher-------------
:: ----------------------------------------------------------
echo --- Disable 3DES (Triple DES) cipher
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168" /f /v Enabled /t REG_DWORD /d 0x00000000       
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable MD5 hash function-----------------
:: ----------------------------------------------------------
echo --- Disable MD5 hash function
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" /f /v Enabled /t REG_DWORD /d 0x00000000
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Disable SHA1-----------------------
:: ----------------------------------------------------------
echo --- Disable SHA1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" /f /v Enabled /t REG_DWORD /d 0x00000000
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable null cipher--------------------
:: ----------------------------------------------------------
echo --- Disable null cipher
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" /f /v Enabled /t REG_DWORD /d 0x00000000
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Force not to respond to renegotiation requests------
:: ----------------------------------------------------------
echo --- Force not to respond to renegotiation requests
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f /v AllowInsecureRenegoClients /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f /v AllowInsecureRenegoServers /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f /v DisableRenegoOnServer /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f /v UseScsvForTls /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable DTLS 1.0---------------------
:: ----------------------------------------------------------
echo --- Disable DTLS 1.0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable DTLS 1.1---------------------
:: ----------------------------------------------------------
echo --- Disable DTLS 1.1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Enable DTLS 1.3----------------------
:: ----------------------------------------------------------
echo --- Enable DTLS 1.3
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" /f /v Enabled /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" /f /v Enabled /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000000
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable TLS 1.0----------------------
:: ----------------------------------------------------------
echo --- Disable TLS 1.0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v3.0" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v3.0" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Disable TLS 1.1----------------------
:: ----------------------------------------------------------
echo --- Disable TLS 1.1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Enable TLS 1.3----------------------
:: ----------------------------------------------------------
echo --- Enable TLS 1.3
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /f /v Enabled /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /f /v Enabled /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000000
:: ----------------------------------------------------------


:: Enabling Strong Authentication for .NET applications (TLS 1.2)
echo --- Enabling Strong Authentication for .NET applications (TLS 1.2)
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v3.0" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v3.0" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Disable SSLv2-----------------------
:: ----------------------------------------------------------
echo --- Disable SSLv2
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Disable SSLv3-----------------------
:: ----------------------------------------------------------
echo --- Disable SSLv3
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /f /v Enabled /t REG_DWORD /d 0x00000000
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable Smart Screen-------------------
:: ----------------------------------------------------------
echo --- Disable Smart Screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f 
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Disable scheduled On Demand anti malware scanner (MRT)--
:: ----------------------------------------------------------
echo --- Disable scheduled On Demand anti malware scanner (MRT)
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable automatic updates-----------------
:: ----------------------------------------------------------
echo --- Disable automatic updates
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t "REG_DWORD" /d "2" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallTime" /t "REG_DWORD" /d "3" /f
sc stop "UsoSvc" & sc config "UsoSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Turn off Windows Firewall-----------------
:: ----------------------------------------------------------
echo --- Turn off Windows Firewall
netsh advfirewall set allprofiles state off
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Microsoft Defender Antivirus-----------
:: ----------------------------------------------------------
echo --- Disable Microsoft Defender Antivirus
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: Disable the Potentially Unwanted Application (PUA) feature
echo --- Disable the Potentially Unwanted Application (PUA) feature
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Turn off enhanced notifications--------------
:: ----------------------------------------------------------
echo --- Turn off enhanced notifications
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Windows Defender logging-------------
:: ----------------------------------------------------------
echo --- Disable Windows Defender logging
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Turn off block at first sight---------------
:: ----------------------------------------------------------
echo --- Turn off block at first sight
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable behavior monitoring----------------
:: ----------------------------------------------------------
echo --- Disable behavior monitoring
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable scanning for all downloaded files and attachments-
:: ----------------------------------------------------------
echo --- Disable scanning for all downloaded files and attachments
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable monitoring file and program activity-------
:: ----------------------------------------------------------
echo --- Disable monitoring file and program activity
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Disable automatically taking action on all detected tasks-
:: ----------------------------------------------------------
echo --- Disable automatically taking action on all detected tasks
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable process scanning on real-time protection-----
:: ----------------------------------------------------------
echo --- Disable process scanning on real-time protection
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Defender ExploitGuard task--------
:: ----------------------------------------------------------
echo --- Disable Windows Defender ExploitGuard task
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Disable Windows Defender Cache Maintenance task------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Cache Maintenance task
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Windows Defender Cleanup task-----------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Cleanup task
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Disable Windows Defender Scheduled Scan task-------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Scheduled Scan task
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Defender Verification task--------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Verification task
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Defender Firewall service---------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Firewall service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MpsSvc" /v "Start" /t REG_DWORD /d "4" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Disable Windows Defender Antivirus service--------
:: ----------------------------------------------------------
echo --- Disable Windows Defender Antivirus service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Disable Microsoft Defender Antivirus Boot Driver service-
:: ----------------------------------------------------------
echo --- Disable Microsoft Defender Antivirus Boot Driver service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f
:: ----------------------------------------------------------


:: Disable Microsoft Defender Antivirus Mini-Filter Driver service
echo --- Disable Microsoft Defender Antivirus Mini-Filter Driver service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
:: ----------------------------------------------------------


:: Disable Microsoft Defender Antivirus Network Inspection System Driver service
echo --- Disable Microsoft Defender Antivirus Network Inspection System Driver service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
:: ----------------------------------------------------------


:: Disable Microsoft Defender Antivirus Network Inspection service
echo --- Disable Microsoft Defender Antivirus Network Inspection service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Disable Windows Security service-------------
:: ----------------------------------------------------------
echo --- Disable Windows Security service
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable lock screen app notifications-----------
:: ----------------------------------------------------------
echo --- Disable lock screen app notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLockScreenAppNotifications" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable Live Tiles push notifications-----------
:: ----------------------------------------------------------
echo --- Disable Live Tiles push notifications
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Turn off "Look For An App In The Store" option------
:: ----------------------------------------------------------
echo --- Turn off "Look For An App In The Store" option
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Do not show recently used files in Quick Access------
:: ----------------------------------------------------------
echo --- Do not show recently used files in Quick Access
if %PROCESSOR_ARCHITECTURE%==x86 ( REM is 32 bit?
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /d 0 /t REG_DWORD /f
) else (
    reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
    reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Sync Provider Notifications------------
:: ----------------------------------------------------------
echo --- Disable Sync Provider Notifications
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /d 0 /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Turn hibernate off to disable sleep for quick start----
:: ----------------------------------------------------------
echo --- Turn hibernate off to disable sleep for quick start
powercfg -h off
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Enable camera on/off OSD notifications----------
:: ----------------------------------------------------------
echo --- Enable camera on/off OSD notifications
reg add "HKLM\SOFTWARE\Microsoft\OEM\Device\Capture" /v "NoPhysicalCameraLED" /d 1 /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Disable online tips--------------------
:: ----------------------------------------------------------
echo --- Disable online tips
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Turn off Internet File Association service--------
:: ----------------------------------------------------------
echo --- Turn off Internet File Association service
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Turn off the "Order Prints" picture task---------
:: ----------------------------------------------------------
echo --- Turn off the "Order Prints" picture task
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoOnlinePrintsWizard" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Disable the file and folder Publish to Web option-----
:: ----------------------------------------------------------
echo --- Disable the file and folder Publish to Web option
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoPublishingWizard" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Prevent downloading a list of providers for wizards----
:: ----------------------------------------------------------
echo --- Prevent downloading a list of providers for wizards
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoWebServices" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Do not keep history of recently opened documents-----
:: ----------------------------------------------------------
echo --- Do not keep history of recently opened documents
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Clear history of recently opened documents on exit----
:: ----------------------------------------------------------
echo --- Clear history of recently opened documents on exit
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ClearRecentDocsOnExit" /t REG_DWORD /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------3D Objects------------------------
:: ----------------------------------------------------------
echo --- 3D Objects
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------------Desktop--------------------------
:: ----------------------------------------------------------
echo --- Desktop
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------Documents-------------------------
:: ----------------------------------------------------------
echo --- Documents
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------Downloads-------------------------
:: ----------------------------------------------------------
echo --- Downloads
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------------Movies--------------------------
:: ----------------------------------------------------------
echo --- Movies
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------------Music---------------------------
:: ----------------------------------------------------------
echo --- Music
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------------Pictures-------------------------
:: ----------------------------------------------------------
echo --- Pictures
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------Delivery Optimization (P2P Windows Updates)--------
:: ----------------------------------------------------------
echo --- Delivery Optimization (P2P Windows Updates)
sc stop "DoSvc" & sc config "DoSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Microsoft Windows Live ID Service-------------
:: ----------------------------------------------------------
echo --- Microsoft Windows Live ID Service
sc stop "wlidsvc" & sc config "wlidsvc" start=demand
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Program Compatibility Assistant Service----------
:: ----------------------------------------------------------
echo --- Program Compatibility Assistant Service
sc stop "PcaSvc" & sc config "PcaSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Downloaded Maps Manager------------------
:: ----------------------------------------------------------
echo --- Downloaded Maps Manager
sc stop "MapsBroker" & sc config "MapsBroker" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Microsoft Retail Demo experience-------------
:: ----------------------------------------------------------
echo --- Microsoft Retail Demo experience
sc stop "RetailDemo" & sc config "RetailDemo" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Contact data indexing-------------------
:: ----------------------------------------------------------
echo --- Contact data indexing
sc stop "PimIndexMaintenanceSvc" & sc config "PimIndexMaintenanceSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------App user data access-------------------
:: ----------------------------------------------------------
echo --- App user data access
sc stop "UserDataSvc" & sc config "UserDataSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Text messaging----------------------
:: ----------------------------------------------------------
echo --- Text messaging
sc stop "MessagingService" & sc config "MessagingService" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Windows Push Notification Service-------------
:: ----------------------------------------------------------
echo --- Windows Push Notification Service
sc stop "WpnService" & sc config "WpnService" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Volume Shadow Copy Service----------------
:: ----------------------------------------------------------
echo --- Volume Shadow Copy Service
sc stop "VSS" & sc config "VSS" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable NetBios for all interfaces------------
:: ----------------------------------------------------------
echo --- Disable NetBios for all interfaces
Powershell -Command "$key = 'HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces'; Get-ChildItem $key | foreach { Set-ItemProperty -Path \"$key\$($_.pschildname)\" -Name NetbiosOptions -Value 2 -Verbose}"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------User Data Storage (UnistoreSvc) Service----------
:: ----------------------------------------------------------
echo --- User Data Storage (UnistoreSvc) Service
sc stop "UnistoreSvc" & sc config "UnistoreSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Sync Host (OneSyncSvc) Service Service----------
:: ----------------------------------------------------------
echo --- Sync Host (OneSyncSvc) Service Service
sc stop "OneSyncSvc" & sc config "OneSyncSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Xbox Live Auth Manager------------------
:: ----------------------------------------------------------
echo --- Xbox Live Auth Manager
sc stop "XblAuthManager" & sc config "XblAuthManager" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Xbox Live Game Save--------------------
:: ----------------------------------------------------------
echo --- Xbox Live Game Save
sc stop "XblGameSave" & sc config "XblGameSave" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Xbox Live Networking Service---------------
:: ----------------------------------------------------------
echo --- Xbox Live Networking Service
sc stop "XboxNetApiSvc" & sc config "XboxNetApiSvc" start=disabled
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------App Connector app---------------------
:: ----------------------------------------------------------
echo --- App Connector app
PowerShell -Command "Get-AppxPackage 'Microsoft.Appconnector' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------App Installer app---------------------
:: ----------------------------------------------------------
echo --- App Installer app
PowerShell -Command "Get-AppxPackage 'Microsoft.DesktopAppInstaller' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Get Help app-----------------------
:: ----------------------------------------------------------
echo --- Get Help app
PowerShell -Command "Get-AppxPackage 'Microsoft.GetHelp' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Microsoft Tips app--------------------
:: ----------------------------------------------------------
echo --- Microsoft Tips app
PowerShell -Command "Get-AppxPackage 'Microsoft.Getstarted' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Microsoft Messaging app------------------
:: ----------------------------------------------------------
echo --- Microsoft Messaging app
PowerShell -Command "Get-AppxPackage 'Microsoft.Messaging' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Mixed Reality Portal app-----------------
:: ----------------------------------------------------------
echo --- Mixed Reality Portal app
PowerShell -Command "Get-AppxPackage 'Microsoft.MixedReality.Portal' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Feedback Hub app---------------------
:: ----------------------------------------------------------
echo --- Feedback Hub app
PowerShell -Command "Get-AppxPackage 'Microsoft.WindowsFeedbackHub' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Windows Alarms and Clock app---------------
:: ----------------------------------------------------------
echo --- Windows Alarms and Clock app
PowerShell -Command "Get-AppxPackage 'Microsoft.WindowsAlarms' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Windows Camera app--------------------
:: ----------------------------------------------------------
echo --- Windows Camera app
PowerShell -Command "Get-AppxPackage 'Microsoft.WindowsCamera' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Paint 3D app-----------------------
:: ----------------------------------------------------------
echo --- Paint 3D app
PowerShell -Command "Get-AppxPackage 'Microsoft.MSPaint' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Windows Maps app---------------------
:: ----------------------------------------------------------
echo --- Windows Maps app
PowerShell -Command "Get-AppxPackage 'Microsoft.WindowsMaps' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Minecraft for Windows 10 app---------------
:: ----------------------------------------------------------
echo --- Minecraft for Windows 10 app
PowerShell -Command "Get-AppxPackage 'Microsoft.MinecraftUWP' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Microsoft Store app--------------------
:: ----------------------------------------------------------
echo --- Microsoft Store app
PowerShell -Command "Get-AppxPackage 'Microsoft.WindowsStore' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Microsoft People app-------------------
:: ----------------------------------------------------------
echo --- Microsoft People app
PowerShell -Command "Get-AppxPackage 'Microsoft.People' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Microsoft Pay app---------------------
:: ----------------------------------------------------------
echo --- Microsoft Pay app
PowerShell -Command "Get-AppxPackage 'Microsoft.Wallet' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Store Purchase app--------------------
:: ----------------------------------------------------------
echo --- Store Purchase app
PowerShell -Command "Get-AppxPackage 'Microsoft.StorePurchaseApp' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Snip & Sketch app---------------------
:: ----------------------------------------------------------
echo --- Snip & Sketch app
PowerShell -Command "Get-AppxPackage 'Microsoft.ScreenSketch' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Print 3D app-----------------------
:: ----------------------------------------------------------
echo --- Print 3D app
PowerShell -Command "Get-AppxPackage 'Microsoft.Print3D' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Mobile Plans app---------------------
:: ----------------------------------------------------------
echo --- Mobile Plans app
PowerShell -Command "Get-AppxPackage 'Microsoft.OneConnect' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Microsoft Solitaire Collection app------------
:: ----------------------------------------------------------
echo --- Microsoft Solitaire Collection app
PowerShell -Command "Get-AppxPackage 'Microsoft.MicrosoftSolitaireCollection' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Microsoft Sticky Notes app----------------
:: ----------------------------------------------------------
echo --- Microsoft Sticky Notes app
PowerShell -Command "Get-AppxPackage 'Microsoft.MicrosoftStickyNotes' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Mail and Calendar app-------------------
:: ----------------------------------------------------------
echo --- Mail and Calendar app
PowerShell -Command "Get-AppxPackage 'microsoft.windowscommunicationsapps' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Windows Calculator app------------------
:: ----------------------------------------------------------
echo --- Windows Calculator app
PowerShell -Command "Get-AppxPackage 'Microsoft.WindowsCalculator' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Microsoft Photos app-------------------
:: ----------------------------------------------------------
echo --- Microsoft Photos app
PowerShell -Command "Get-AppxPackage 'Microsoft.Windows.Photos' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------Skype app-------------------------
:: ----------------------------------------------------------
echo --- Skype app
PowerShell -Command "Get-AppxPackage 'Microsoft.SkypeApp' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------GroupMe app------------------------
:: ----------------------------------------------------------
echo --- GroupMe app
PowerShell -Command "Get-AppxPackage 'Microsoft.GroupMe10' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Windows Voice Recorder app----------------
:: ----------------------------------------------------------
echo --- Windows Voice Recorder app
PowerShell -Command "Get-AppxPackage 'Microsoft.WindowsSoundRecorder' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Microsoft 3D Builder app-----------------
:: ----------------------------------------------------------
echo --- Microsoft 3D Builder app
PowerShell -Command "Get-AppxPackage 'Microsoft.3DBuilder' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------3D Viewer app-----------------------
:: ----------------------------------------------------------
echo --- 3D Viewer app
PowerShell -Command "Get-AppxPackage 'Microsoft.Microsoft3DViewer' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------MSN Weather app----------------------
:: ----------------------------------------------------------
echo --- MSN Weather app
PowerShell -Command "Get-AppxPackage 'Microsoft.BingWeather' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------MSN Sports app----------------------
:: ----------------------------------------------------------
echo --- MSN Sports app
PowerShell -Command "Get-AppxPackage 'Microsoft.BingSports' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------MSN News app-----------------------
:: ----------------------------------------------------------
echo --- MSN News app
PowerShell -Command "Get-AppxPackage 'Microsoft.BingNews' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------MSN Money app-----------------------
:: ----------------------------------------------------------
echo --- MSN Money app
PowerShell -Command "Get-AppxPackage 'Microsoft.BingFinance' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------HEIF Image Extensions app-----------------
:: ----------------------------------------------------------
echo --- HEIF Image Extensions app
PowerShell -Command "Get-AppxPackage 'Microsoft.HEIFImageExtension' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------VP9 Video Extensions app-----------------
:: ----------------------------------------------------------
echo --- VP9 Video Extensions app
PowerShell -Command "Get-AppxPackage 'Microsoft.VP9VideoExtensions' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Web Media Extensions app-----------------
:: ----------------------------------------------------------
echo --- Web Media Extensions app
PowerShell -Command "Get-AppxPackage 'Microsoft.WebMediaExtensions' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Webp Image Extensions app-----------------
:: ----------------------------------------------------------
echo --- Webp Image Extensions app
PowerShell -Command "Get-AppxPackage 'Microsoft.WebpImageExtension' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------My Office app-----------------------
:: ----------------------------------------------------------
echo --- My Office app
PowerShell -Command "Get-AppxPackage 'Microsoft.MicrosoftOfficeHub' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------OneNote app------------------------
:: ----------------------------------------------------------
echo --- OneNote app
PowerShell -Command "Get-AppxPackage 'Microsoft.Office.OneNote' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------------Sway app-------------------------
:: ----------------------------------------------------------
echo --- Sway app
PowerShell -Command "Get-AppxPackage 'Microsoft.Office.Sway' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Xbox Console Companion app----------------
:: ----------------------------------------------------------
echo --- Xbox Console Companion app
PowerShell -Command "Get-AppxPackage 'Microsoft.XboxApp' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Xbox Live in-game experience app-------------
:: ----------------------------------------------------------
echo --- Xbox Live in-game experience app
PowerShell -Command "Get-AppxPackage 'Microsoft.Xbox.TCUI' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Xbox Game Bar app---------------------
:: ----------------------------------------------------------
echo --- Xbox Game Bar app
PowerShell -Command "Get-AppxPackage 'Microsoft.XboxGamingOverlay' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Xbox Game Bar Plugin appcache---------------
:: ----------------------------------------------------------
echo --- Xbox Game Bar Plugin appcache
PowerShell -Command "Get-AppxPackage 'Microsoft.XboxGameOverlay' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Xbox Identity Provider app----------------
:: ----------------------------------------------------------
echo --- Xbox Identity Provider app
PowerShell -Command "Get-AppxPackage 'Microsoft.XboxIdentityProvider' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Xbox Speech To Text Overlay app--------------
:: ----------------------------------------------------------
echo --- Xbox Speech To Text Overlay app
PowerShell -Command "Get-AppxPackage 'Microsoft.XboxSpeechToTextOverlay' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Groove Music app---------------------
:: ----------------------------------------------------------
echo --- Groove Music app
PowerShell -Command "Get-AppxPackage 'Microsoft.ZuneMusic' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Movies & TV app----------------------
:: ----------------------------------------------------------
echo --- Movies & TV app
PowerShell -Command "Get-AppxPackage 'Microsoft.ZuneVideo' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Your Phone Companion app-----------------
:: ----------------------------------------------------------
echo --- Your Phone Companion app
PowerShell -Command "Get-AppxPackage 'Microsoft.WindowsPhone' | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage 'Microsoft.Windows.Phone' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Communications - Phone app----------------
:: ----------------------------------------------------------
echo --- Communications - Phone app
PowerShell -Command "Get-AppxPackage 'Microsoft.CommsPhone' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Your Phone app----------------------
:: ----------------------------------------------------------
echo --- Your Phone app
PowerShell -Command "Get-AppxPackage 'Microsoft.YourPhone' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Microsoft Advertising app-----------------
:: ----------------------------------------------------------
echo --- Microsoft Advertising app
PowerShell -Command "Get-AppxPackage 'Microsoft.Advertising.Xaml' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Remote Desktop app--------------------
:: ----------------------------------------------------------
echo --- Remote Desktop app
PowerShell -Command "Get-AppxPackage 'Microsoft.RemoteDesktop' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Network Speed Test app------------------
:: ----------------------------------------------------------
echo --- Network Speed Test app
PowerShell -Command "Get-AppxPackage 'Microsoft.NetworkSpeedTest' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Microsoft To Do app--------------------
:: ----------------------------------------------------------
echo --- Microsoft To Do app
PowerShell -Command "Get-AppxPackage 'Microsoft.Todos' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------Shazam app------------------------
:: ----------------------------------------------------------
echo --- Shazam app
PowerShell -Command "Get-AppxPackage 'ShazamEntertainmentLtd.Shazam' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Candy Crush Saga app-------------------
:: ----------------------------------------------------------
echo --- Candy Crush Saga app
PowerShell -Command "Get-AppxPackage 'king.com.CandyCrushSaga' | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage 'king.com.CandyCrushSodaSaga' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------------Flipboard app-----------------------
:: ----------------------------------------------------------
echo --- Flipboard app
PowerShell -Command "Get-AppxPackage 'Flipboard.Flipboard' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Twitter app------------------------
:: ----------------------------------------------------------
echo --- Twitter app
PowerShell -Command "Get-AppxPackage '9E2F88E3.Twitter' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------iHeartRadio app----------------------
:: ----------------------------------------------------------
echo --- iHeartRadio app
PowerShell -Command "Get-AppxPackage 'ClearChannelRadioDigital.iHeartRadio' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Duolingo app-----------------------
:: ----------------------------------------------------------
echo --- Duolingo app
PowerShell -Command "Get-AppxPackage 'D5EA27B7.Duolingo-LearnLanguagesforFree' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Photoshop Express app-------------------
:: ----------------------------------------------------------
echo --- Photoshop Express app
PowerShell -Command "Get-AppxPackage 'AdobeSystemIncorporated.AdobePhotoshop' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Pandora app------------------------
:: ----------------------------------------------------------
echo --- Pandora app
PowerShell -Command "Get-AppxPackage 'PandoraMediaInc.29680B314EFC2' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Eclipse Manager app--------------------
:: ----------------------------------------------------------
echo --- Eclipse Manager app
PowerShell -Command "Get-AppxPackage '46928bounde.EclipseManager' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Code Writer app----------------------
:: ----------------------------------------------------------
echo --- Code Writer app
PowerShell -Command "Get-AppxPackage 'ActiproSoftwareLLC.562882FEEB491' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Spotify app------------------------
:: ----------------------------------------------------------
echo --- Spotify app
PowerShell -Command "Get-AppxPackage 'SpotifyAB.SpotifyMusic' | Remove-AppxPackage"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------File Picker app----------------------
:: ----------------------------------------------------------
echo --- File Picker app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers '1527c705-839a-4832-9118-54d4Bd6a0c89'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------File Explorer app---------------------
:: ----------------------------------------------------------
echo --- File Explorer app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'c5e2524a-ea46-4f67-841f-6a9465d9d515'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------App Resolver UX app--------------------
:: ----------------------------------------------------------
echo --- App Resolver UX app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'E2A4F912-2574-4A75-9BB0-0D023378592B'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Add Suggested Folders To Library app-----------
:: ----------------------------------------------------------
echo --- Add Suggested Folders To Library app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'InputApp'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: Microsoft AAD Broker Plugin app (breaks Office app authentication)
echo --- Microsoft AAD Broker Plugin app (breaks Office app authentication)
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.AAD.BrokerPlugin'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Microsoft Accounts Control app--------------
:: ----------------------------------------------------------
echo --- Microsoft Accounts Control app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.AccountsControl'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Microsoft Async Text Service app-------------
:: ----------------------------------------------------------
echo --- Microsoft Async Text Service app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.AsyncTextService'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------Start app-------------------------
:: ----------------------------------------------------------
echo --- Start app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.ShellExperienceHost'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Contact Support app--------------------
:: ----------------------------------------------------------
echo --- Contact Support app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Windows.ContactSupport'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Settings app-----------------------
:: ----------------------------------------------------------
echo --- Settings app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Windows.immersivecontrolpanel'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Windows Print 3D app-------------------
:: ----------------------------------------------------------
echo --- Windows Print 3D app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Windows.Print3D'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------------Print UI app-----------------------
:: ----------------------------------------------------------
echo --- Print UI app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Windows.PrintDialog'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Bio enrollment app (breaks biometric authentication)---
:: ----------------------------------------------------------
echo --- Bio enrollment app (breaks biometric authentication)
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.BioEnrollment'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Cred Dialog Host app-------------------
:: ----------------------------------------------------------
echo --- Cred Dialog Host app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.CredDialogHost'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------------EC app--------------------------
:: ----------------------------------------------------------
echo --- EC app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.ECApp'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Lock app (shows lock screen)---------------
:: ----------------------------------------------------------
echo --- Lock app (shows lock screen)
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.LockApp'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Microsoft Edge app--------------------
:: ----------------------------------------------------------
echo --- Microsoft Edge app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.MicrosoftEdge'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Microsoft Edge Dev Tools Client app------------
:: ----------------------------------------------------------
echo --- Microsoft Edge Dev Tools Client app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.MicrosoftEdgeDevToolsClient'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Microsoft PPI Projection app---------------
:: ----------------------------------------------------------
echo --- Microsoft PPI Projection app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.PPIProjection'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Win32 Web View Host app / Desktop App Web Viewer-----
:: ----------------------------------------------------------
echo --- Win32 Web View Host app / Desktop App Web Viewer
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Win32WebViewHost'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------------ChxApp app------------------------
:: ----------------------------------------------------------
echo --- ChxApp app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.Apprep.ChxApp'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Assigned Access Lock App app---------------
:: ----------------------------------------------------------
echo --- Assigned Access Lock App app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.AssignedAccessLockApp'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Capture Picker app--------------------
:: ----------------------------------------------------------
echo --- Capture Picker app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.CapturePicker'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Cloud Experience Host app-----------------
:: ----------------------------------------------------------
echo --- Cloud Experience Host app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.CloudExperienceHost'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: Content Delivery Manager app (automatically installs apps)
echo --- Content Delivery Manager app (automatically installs apps)
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.ContentDeliveryManager'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Cortana app (breaks Windows search)------------
:: ----------------------------------------------------------
echo --- Cortana app (breaks Windows search)
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.Cortana'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Holographic First Run app-----------------
:: ----------------------------------------------------------
echo --- Holographic First Run app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.Holographic.FirstRun'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------OOBE Network Captive Port app---------------
:: ----------------------------------------------------------
echo --- OOBE Network Captive Port app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.OOBENetworkCaptivePortal'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------OOBE Network Connection Flow app-------------
:: ----------------------------------------------------------
echo --- OOBE Network Connection Flow app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.OOBENetworkConnectionFlow'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Windows 10 Family Safety / Parental Controls app-----
:: ----------------------------------------------------------
echo --- Windows 10 Family Safety / Parental Controls app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.ParentalControls'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: My People / People Bar App on taskbar (People Experience Host)
echo --- My People / People Bar App on taskbar (People Experience Host)
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.PeopleExperienceHost'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Pinning Confirmation Dialog app--------------
:: ----------------------------------------------------------
echo --- Pinning Confirmation Dialog app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.PinningConfirmationDialog'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Windows Security GUI (Sec Health UI) app---------
:: ----------------------------------------------------------
echo --- Windows Security GUI (Sec Health UI) app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.SecHealthUI'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Secondary Tile Experience app---------------
:: ----------------------------------------------------------
echo --- Secondary Tile Experience app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.SecondaryTileExperience'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: Secure Assessment Browser app (breaks Microsoft Intune/Graph)
echo --- Secure Assessment Browser app (breaks Microsoft Intune/Graph)
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.Windows.SecureAssessmentBrowser'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Windows Feedback app-------------------
:: ----------------------------------------------------------
echo --- Windows Feedback app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.WindowsFeedback'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----Xbox Game Callable UI app (breaks Xbox Live games)----
:: ----------------------------------------------------------
echo --- Xbox Game Callable UI app (breaks Xbox Live games)
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Microsoft.XboxGameCallableUI'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------CBS Preview app----------------------
:: ----------------------------------------------------------
echo --- CBS Preview app
PowerShell -Command " $package = (Get-AppxPackage -AllUsers 'Windows.CBSPreview'); if (!$package) { Write-Host 'Not installed'; exit 0; } $directories = @($package.InstallLocation, \"$env:LOCALAPPDATA\Packages\$($package.PackageFamilyName)\"); foreach($dir in $directories) { if ( !$dir -Or !(Test-Path \"$dir\") ) { continue; } cmd /c takeown /f \"$dir\" /r /d y | Out-Null; cmd /c icacls \"$dir\" /grant administrators:F /t | Out-Null; $files = Get-ChildItem -File -Path $dir -Recurse -Force; foreach($file in $files) { if($file.Name.EndsWith('.OLD')) { continue; } $newName =  $file.FullName + '.OLD'; Write-Host \"Rename '$($file.FullName)' to '$newName'\"; Move-Item -LiteralPath \"$($file.FullName)\" -Destination \"$newName\" -Force; } }; "
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Kill OneDrive process-------------------
:: ----------------------------------------------------------
echo --- Kill OneDrive process
taskkill /f /im OneDrive.exe
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------Uninstall OneDrive--------------------
:: ----------------------------------------------------------
echo --- Uninstall OneDrive
if %PROCESSOR_ARCHITECTURE%==x86 (
    %SystemRoot%\System32\OneDriveSetup.exe /uninstall 2>null
) else (
    %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall 2>null
)
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Remove OneDrive leftovers-----------------
:: ----------------------------------------------------------
echo --- Remove OneDrive leftovers
rd "%UserProfile%\OneDrive" /q /s
rd "%LocalAppData%\Microsoft\OneDrive" /q /s
rd "%ProgramData%\Microsoft OneDrive" /q /s
rd "%SystemDrive%\OneDriveTemp" /q /s
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Delete OneDrive shortcuts-----------------
:: ----------------------------------------------------------
echo --- Delete OneDrive shortcuts
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Microsoft OneDrive.lnk" /s /f /q
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
del "%USERPROFILE%\Links\OneDrive.lnk" /s /f /q
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Disable usage of OneDrive-----------------
:: ----------------------------------------------------------
echo --- Disable usage of OneDrive
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /t REG_DWORD /v "DisableFileSyncNGSC" /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /t REG_DWORD /v "DisableFileSync" /d 1 /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Prevent automatic OneDrive install for current user----
:: ----------------------------------------------------------
echo --- Prevent automatic OneDrive install for current user
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Prevent automatic OneDrive install for new users-----
:: ----------------------------------------------------------
echo --- Prevent automatic OneDrive install for new users
reg load "HKU\Default" "%SystemDrive%\Users\Default\NTUSER.DAT" 
reg delete "HKU\Default\software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "HKU\Default"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Remove OneDrive from explorer menu------------
:: ----------------------------------------------------------
echo --- Remove OneDrive from explorer menu
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
reg add "HKCR\Wow6432Node\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Delete all OneDrive related Services-----------
:: ----------------------------------------------------------
echo --- Delete all OneDrive related Services
for /f "tokens=1 delims=," %%x in ('schtasks /query /fo csv ^| find "OneDrive"') do schtasks /Delete /TN %%x /F
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Delete OneDrive path from registry------------
:: ----------------------------------------------------------
echo --- Delete OneDrive path from registry
reg delete "HKCU\Environment" /v "OneDrive" /f
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Direct Play feature--------------------
:: ----------------------------------------------------------
echo --- Direct Play feature
dism /Online /Disable-Feature /FeatureName:"DirectPlay" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Internet Explorer feature-----------------
:: ----------------------------------------------------------
echo --- Internet Explorer feature
dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-x64" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-x84" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Internet-Explorer-Optional-amd64" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Legacy Components feature-----------------
:: ----------------------------------------------------------
echo --- Legacy Components feature
dism /Online /Disable-Feature /FeatureName:"LegacyComponents" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Media Features feature------------------
:: ----------------------------------------------------------
echo --- Media Features feature
dism /Online /Disable-Feature /FeatureName:"MediaPlayback" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Scan Management feature------------------
:: ----------------------------------------------------------
echo --- Scan Management feature
dism /Online /Disable-Feature /FeatureName:"ScanManagementConsole" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Windows Fax and Scan feature---------------
:: ----------------------------------------------------------
echo --- Windows Fax and Scan feature
dism /Online /Disable-Feature /FeatureName:"FaxServicesClientPackage" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Windows Media Player feature---------------
:: ----------------------------------------------------------
echo --- Windows Media Player feature
dism /Online /Disable-Feature /FeatureName:"WindowsMediaPlayer" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Windows Search feature------------------
:: ----------------------------------------------------------
echo --- Windows Search feature
dism /Online /Disable-Feature /FeatureName:"SearchEngine-Client-Package" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------Telnet Client feature-------------------
:: ----------------------------------------------------------
echo --- Telnet Client feature
dism /Online /Disable-Feature /FeatureName:"TelnetClient" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Net.TCP Port Sharing feature---------------
:: ----------------------------------------------------------
echo --- Net.TCP Port Sharing feature
dism /Online /Disable-Feature /FeatureName:"WCF-TCP-PortSharing45" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------SMB Direct feature--------------------
:: ----------------------------------------------------------
echo --- SMB Direct feature
dism /Online /Disable-Feature /FeatureName:"SmbDirect" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------TFTP Client feature--------------------
:: ----------------------------------------------------------
echo --- TFTP Client feature
dism /Online /Disable-Feature /FeatureName:"TFTP" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------Hyper-V feature----------------------
:: ----------------------------------------------------------
echo --- Hyper-V feature
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-All" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Hyper-V GUI Management Tools feature-----------
:: ----------------------------------------------------------
echo --- Hyper-V GUI Management Tools feature
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-Clients" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Hyper-V Management Tools feature-------------
:: ----------------------------------------------------------
echo --- Hyper-V Management Tools feature
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Tools-All" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Hyper-V Module for Windows PowerShell feature-------
:: ----------------------------------------------------------
echo --- Hyper-V Module for Windows PowerShell feature
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-PowerShell" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Print and Document Services feature------------
:: ----------------------------------------------------------
echo --- Print and Document Services feature
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-Features" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Work Folders Client feature----------------
:: ----------------------------------------------------------
echo --- Work Folders Client feature
dism /Online /Disable-Feature /FeatureName:"WorkFolders-Client" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Internet Printing Client-----------------
:: ----------------------------------------------------------
echo --- Internet Printing Client
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-InternetPrinting-Client" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------LPD Print Service---------------------
:: ----------------------------------------------------------
echo --- LPD Print Service
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-LPDPrintService" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------LPR Port Monitor feature-----------------
:: ----------------------------------------------------------
echo --- LPR Port Monitor feature
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-LPRPortMonitor" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Microsoft Print to PDF feature--------------
:: ----------------------------------------------------------
echo --- Microsoft Print to PDF feature
dism /Online /Disable-Feature /FeatureName:"Printing-PrintToPDFServices-Features" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------XPS Services feature-------------------
:: ----------------------------------------------------------
echo --- XPS Services feature
dism /Online /Disable-Feature /FeatureName:"Printing-XPSServices-Features" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------------XPS Viewer feature--------------------
:: ----------------------------------------------------------
echo --- XPS Viewer feature
dism /Online /Disable-Feature /FeatureName:"Xps-Foundation-Xps-Viewer" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------DirectX Configuration Database capability---------
:: ----------------------------------------------------------
echo --- DirectX Configuration Database capability
Powershell -Command "Get-WindowsCapability -Online -Name "DirectX.Configuration.Database*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Internet Explorer 11 capability--------------
:: ----------------------------------------------------------
echo --- Internet Explorer 11 capability
Powershell -Command "Get-WindowsCapability -Online -Name "Browser.InternetExplorer*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Math Recognizer capability----------------
:: ----------------------------------------------------------
echo --- Math Recognizer capability
Powershell -Command "Get-WindowsCapability -Online -Name "MathRecognizer*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --OneSync capability (breaks Mail, People, and Calendar)--
:: ----------------------------------------------------------
echo --- OneSync capability (breaks Mail, People, and Calendar)
Powershell -Command "Get-WindowsCapability -Online -Name "OneCoreUAP.OneSync*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------OpenSSH client capability-----------------
:: ----------------------------------------------------------
echo --- OpenSSH client capability
Powershell -Command "Get-WindowsCapability -Online -Name "OpenSSH.Client*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------PowerShell ISE capability-----------------
:: ----------------------------------------------------------
echo --- PowerShell ISE capability
Powershell -Command "Get-WindowsCapability -Online -Name "Microsoft.Windows.PowerShell.ISE*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Print Management Console capability------------
:: ----------------------------------------------------------
echo --- Print Management Console capability
Powershell -Command "Get-WindowsCapability -Online -Name "Print.Management.Console*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Quick Assist capability------------------
:: ----------------------------------------------------------
echo --- Quick Assist capability
Powershell -Command "Get-WindowsCapability -Online -Name "App.Support.QuickAssist*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Steps Recorder capability-----------------
:: ----------------------------------------------------------
echo --- Steps Recorder capability
Powershell -Command "Get-WindowsCapability -Online -Name "App.StepsRecorder*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Windows Fax and Scan capability--------------
:: ----------------------------------------------------------
echo --- Windows Fax and Scan capability
Powershell -Command "Get-WindowsCapability -Online -Name "Print.Fax.Scan*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------.NET Framework capability-----------------
:: ----------------------------------------------------------
echo --- .NET Framework capability
Powershell -Command "Get-WindowsCapability -Online -Name "NetFX3*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------Mixed Reality capability-----------------
:: ----------------------------------------------------------
echo --- Mixed Reality capability
Powershell -Command "Get-WindowsCapability -Online -Name "Analog.Holographic.Desktop*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Wireless Display capability----------------
:: ----------------------------------------------------------
echo --- Wireless Display capability
Powershell -Command "Get-WindowsCapability -Online -Name "App.WirelessDisplay.Connect*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Accessibility - Braille Support capability--------
:: ----------------------------------------------------------
echo --- Accessibility - Braille Support capability
Powershell -Command "Get-WindowsCapability -Online -Name "Accessibility.Braille*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Developer Mode capability-----------------
:: ----------------------------------------------------------
echo --- Developer Mode capability
Powershell -Command "Get-WindowsCapability -Online -Name "Tools.DeveloperMode.Core*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------Graphics Tools capability-----------------
:: ----------------------------------------------------------
echo --- Graphics Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Tools.Graphics.DirectX*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------------IrDA capability----------------------
:: ----------------------------------------------------------
echo --- IrDA capability
Powershell -Command "Get-WindowsCapability -Online -Name "Network.Irda*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Microsoft WebDriver capability--------------
:: ----------------------------------------------------------
echo --- Microsoft WebDriver capability
Powershell -Command "Get-WindowsCapability -Online -Name "Microsoft.WebDriver*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------MSIX Packaging Tool Driver capability-----------
:: ----------------------------------------------------------
echo --- MSIX Packaging Tool Driver capability
Powershell -Command "Get-WindowsCapability -Online -Name "Msix.PackagingTool.Driver*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------------OpenSSH Server capability-----------------
:: ----------------------------------------------------------
echo --- OpenSSH Server capability
Powershell -Command "Get-WindowsCapability -Online -Name "OpenSSH.Server*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: Windows Emergency Management Services and Serial Console capability
echo --- Windows Emergency Management Services and Serial Console capability
Powershell -Command "Get-WindowsCapability -Online -Name "Windows.Desktop.EMS-SAC.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------------XPS Viewer capability-------------------
:: ----------------------------------------------------------
echo --- XPS Viewer capability
Powershell -Command "Get-WindowsCapability -Online -Name "XPS.Viewer*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: RAS Connection Manager Administration Kit (CMAK) capability
echo --- RAS Connection Manager Administration Kit (CMAK) capability
Powershell -Command "Get-WindowsCapability -Online -Name "RasCMAK.Client*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------------RIP Listener capability------------------
:: ----------------------------------------------------------
echo --- RIP Listener capability
Powershell -Command "Get-WindowsCapability -Online -Name "RIP.Listener*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---Simple Network Management Protocol (SNMP) capability---
:: ----------------------------------------------------------
echo --- Simple Network Management Protocol (SNMP) capability
Powershell -Command "Get-WindowsCapability -Online -Name "SNMP.Client*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------SNMP WMI Provider capability---------------
:: ----------------------------------------------------------
echo --- SNMP WMI Provider capability
Powershell -Command "Get-WindowsCapability -Online -Name "WMI-SNMP-Provider.Client*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Enterprise Cloud Print capability-------------
:: ----------------------------------------------------------
echo --- Enterprise Cloud Print capability
Powershell -Command "Get-WindowsCapability -Online -Name "Print.EnterpriseCloudPrint*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------Mopria Cloud Service capability--------------
:: ----------------------------------------------------------
echo --- Mopria Cloud Service capability
Powershell -Command "Get-WindowsCapability -Online -Name "Print.MopriaCloudService*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: Active Directory Domain Services and Lightweight Directory Services Tools capability
echo --- Active Directory Domain Services and Lightweight Directory Services Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: BitLocker Drive Encryption Administration Utilities capability
echo --- BitLocker Drive Encryption Administration Utilities capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.BitLocker.Recovery.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Active Directory Certificate Services Tools v-------
:: ----------------------------------------------------------
echo --- Active Directory Certificate Services Tools v
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.CertificateServices.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------DHCP Server Tools capability---------------
:: ----------------------------------------------------------
echo --- DHCP Server Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.DHCP.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------DNS Server Tools capability----------------
:: ----------------------------------------------------------
echo --- DNS Server Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.Dns.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Failover Clustering Tools capability-----------
:: ----------------------------------------------------------
echo --- Failover Clustering Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.FailoverCluster.Management.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------File Services Tools capability--------------
:: ----------------------------------------------------------
echo --- File Services Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.FileServices.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Group Policy Management Tools capability---------
:: ----------------------------------------------------------
echo --- Group Policy Management Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------IP Address Management (IPAM) Client capability------
:: ----------------------------------------------------------
echo --- IP Address Management (IPAM) Client capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.IPAM.Client.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Data Center Bridging LLDP Tools capability--------
:: ----------------------------------------------------------
echo --- Data Center Bridging LLDP Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.LLDP.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Network Controller Management Tools capability------
:: ----------------------------------------------------------
echo --- Network Controller Management Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.NetworkController.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Network Load Balancing Tools capability----------
:: ----------------------------------------------------------
echo --- Network Load Balancing Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.NetworkLoadBalancing.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------Remote Access Management Tools capability---------
:: ----------------------------------------------------------
echo --- Remote Access Management Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.RemoteAccess.Management.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -------------------Server Manager Tools-------------------
:: ----------------------------------------------------------
echo --- Server Manager Tools
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.ServerManager.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Shielded VM Tools capability---------------
:: ----------------------------------------------------------
echo --- Shielded VM Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.Shielded.VM.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -Storage Replica Module for Windows PowerShell capability-
:: ----------------------------------------------------------
echo --- Storage Replica Module for Windows PowerShell capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.StorageReplica.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Volume Activation Tools capability------------
:: ----------------------------------------------------------
echo --- Volume Activation Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.VolumeActivation.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----Windows Server Update Services Tools capability------
:: ----------------------------------------------------------
echo --- Windows Server Update Services Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.WSUS.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --Storage Migration Service Management Tools capability---
:: ----------------------------------------------------------
echo --- Storage Migration Service Management Tools capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.StorageMigrationService.Management.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: Systems Insights Module for Windows PowerShell capability-
:: ----------------------------------------------------------
echo --- Systems Insights Module for Windows PowerShell capability
Powershell -Command "Get-WindowsCapability -Online -Name "Rsat.SystemInsights.Management.Tools*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Windows Storage Management capability-----------
:: ----------------------------------------------------------
echo --- Windows Storage Management capability
Powershell -Command "Get-WindowsCapability -Online -Name "Microsoft.Windows.StorageManagement*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------OneCore Storage Management capability-----------
:: ----------------------------------------------------------
echo --- OneCore Storage Management capability
Powershell -Command "Get-WindowsCapability -Online -Name "Microsoft.OneCore.StorageManagement*" | Remove-WindowsCapability -Online"
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Change NTP (time) server to pool.ntp.org---------
:: ----------------------------------------------------------
echo --- Change NTP (time) server to pool.ntp.org
:: Configure time source
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"
:: Restart time service if running
SC queryex "w32time"|Find "STATE"|Find /v "RUNNING">Nul||(
    net stop w32time
    net start w32time
)
:: Sync now
w32tm /config /update
w32tm /resync
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable Reserved Storage for updates-----------
:: ----------------------------------------------------------
echo --- Disable Reserved Storage for updates
dism /online /Set-ReservedStorageState /State:Disabled /NoRestart
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "MiscPolicyInfo" /t REG_DWORD /d "2" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d "0" /f
:: ----------------------------------------------------------


pause
exit /b 0