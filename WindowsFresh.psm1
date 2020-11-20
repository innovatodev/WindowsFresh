function Check
{
	Set-StrictMode -Version Latest
	$Global:Error.Clear()
	switch ([Environment]::Is64BitOperatingSystem)
	{
		$false
		{
			Write-Output "32bits OS not supported"
			Exit
		}
	}
}
If (!(Test-Path "HKCR:")) {
	New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
}
# Uninstall UWP apps with whitelist
Function UninstallUWP
{
	Write-Output "UninstallUWP"
	$WHITELIST = "549981C3F5F10|Windows.Photos|WindowsCalculator|WindowsCamera|GamingApp|GamingServices|Xbox|DesktopAppInstaller|StorePurchaseApp|WindowsStore|WebMediaExtensions|Nvidia|IntelGraphics|Nahimic|AdvancedMicroDevicesInc|Realtek"
	Get-AppxPackage -PackageTypeFilter Bundle | Where-Object { $_.Name -NotMatch $WHITELIST } | Where-Object { $_.NonRemovable -notlike 'True' } | Remove-AppxPackage | Out-Null
}
# Disable services with blacklist
Function DisableServices
{
	Write-Output "DisableServices"
	$BLACKLIST = "RemoteAccess|RemoteRegistry|WSearch"
    Get-Service | Where-Object { $_.Name -Match $BLACKLIST } | Where-Object { $_.StartType -notlike 'Disabled' } | Set-Service -StartupType Disabled | Out-Null
}
# Disable tasks with blacklist
Function DisableTasks
{
	Write-Output "DisableTasks"
	$BLACKLIST = "Microsoft Compatibility Appraiser|Proxy|Consolidator|Microsoft-Windows-DiskDiagnosticDataCollector|GatherNetworkInfo"
	Get-ScheduledTask | Where-Object { $_.TaskName -Match $BLACKLIST } | Where-Object { $_.State -notlike 'Disabled' } | Disable-ScheduledTask | Out-Null
}
# Disable features with blacklist
Function DisableFeatures
{
	Write-Output "DisableFeatures"
	$BLACKLIST = "Printing|SearchEngine|MSRDC-Infrastructure|WCF-Services45|WCF-TCP-PortSharing45|MediaPlayback|WindowsMediaPlayer|SmbDirect|Internet-Explorer|WorkFolders|PowerShellV2"
	Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -Match $BLACKLIST }  | Where-Object { $_.State -like 'Enabled' } | Disable-WindowsOptionalFeature -Online -NoRestart | Out-Null
}
# Disable Capabilities with blacklist
Function DisableCapabilities
{
	Write-Output "DisableCapabilities"
	$BLACKLIST = "StepsRecorder|QuickAssist|InternetExplorer|Hello.Face|MathRecognizer|WindowsMediaPlayer|WordPad|OneSync|OpenSSH|Print"
	Get-WindowsCapability -Online | Where-Object { $_.Name -Match $BLACKLIST } | Where-Object { $_.State -like 'Installed' } | Remove-WindowsCapability -Online | Out-Null
}
function RemoveStartup
{
	Write-Output "RemoveStartup"
	$BLACKLIST = "OneDrive|SecurityHealth"
	Get-Item -path @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		#"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
		"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
		#"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
		#"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
	) | Where-Object ValueCount -ne 0 |
		ForEach-Object {
			foreach ($name in $_.GetValueNames()) {
				$ENTRY = [PSCustomObject]@{
					Name     = $name
					Value    = $_.GetValue($name)
					ShouldDisable = $name -match $BLACKLIST
					Path          = $_.PSPath
				}
				If ($ENTRY.ShouldDisable)
				{
					Write-Output $ENTRY.Path $ENTRY.Name
					Remove-ItemProperty -Path $ENTRY.Path -Name $ENTRY.Name | Out-Null
				}
			}
		}
}

Function UnpinStartMenu
{
	Write-Output "UnpinStartMenu"
$StartMenuLayout = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
<LayoutOptions StartTileGroupCellWidth="6" />
	<DefaultLayoutOverride>
		<StartLayoutCollection>
			<defaultlayout:StartLayout GroupCellWidth="6" />
		</StartLayoutCollection>
	</DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
	$StartMenuLayoutPath = "$env:TEMP\StartMenuLayout.xml"
	Set-Content -Path $StartMenuLayoutPath -Value (New-Object -TypeName System.Text.UTF8Encoding).GetBytes($StartMenuLayout) -Encoding Byte -Force | Out-Null
	if (-not (Test-Path -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer))
	{
		New-Item -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Force | Out-Null
	}
	New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -Value 1 -Force | Out-Null
	New-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -Value $StartMenuLayoutPath -Force | Out-Null
	Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore | Out-Null
	Start-Sleep -Seconds 3
	Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name LockedStartLayout -Force -ErrorAction Ignore | Out-Null
	Remove-ItemProperty -Path HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer -Name StartLayoutFile -Force -ErrorAction Ignore | Out-Null
	Stop-Process -Name StartMenuExperienceHost -Force -ErrorAction Ignore | Out-Null
	Get-Item -Path $StartMenuLayoutPath | Remove-Item -Force -ErrorAction Ignore | Out-Null
}
# Disable Cortana
Function DisableCortana
{
	Write-Output "DisableCortana"
	If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Type DWord -Value 0 | Out-Null
	Get-AppxPackage "Microsoft.549981C3F5F10"  | Remove-AppxPackage
}
# Enable Cortana
Function EnableCortana
{
	Write-Output "EnableCortana"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 0 | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCortanaButton" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -Type DWord -Value 1 | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -ErrorAction SilentlyContinue | Out-Null
	Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
# Disable OneDrive
Function DisableOneDrive
{
	Write-Output "DisableOneDrive"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1 | Out-Null
}
# Enable OneDrive
Function EnableOneDrive
{
	Write-Output "EnableOneDrive"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ErrorAction SilentlyContinue | Out-Null
}
# Uninstall OneDrive
Function UninstallOneDrive
{
	Write-Output "UninstallOneDrive"
	Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	If ((Get-ChildItem -Path "$env:USERPROFILE\OneDrive" -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
		Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	}
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Install OneDrive
Function InstallOneDrive
{
	Write-Output "InstallOneDrive"
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive -NoNewWindow
}
# Uninstall Windows Store
Function UninstallWindowsStore
{
	Write-Output "UninstallWindowsStore"
	Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Services.Store.Engagement" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.StorePurchaseApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}
# Install Windows Store
Function InstallWindowsStore
{
	Write-Output "InstallWindowsStore"
	Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Services.Store.Engagement" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.StorePurchaseApp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
# Install Windows Photos
Function InstallWindowsPhotos
{
	Write-Output "InstallWindowsPhotos"
	Get-AppxPackage -AllUsers "Microsoft.Windows.Photos" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
# Uninstall Windows Photos
Function UninstallWindowsPhotos
{
	Write-Output "UninstallWindowsPhotos"
	Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
}
# Install Windows Camera
Function InstallWindowsCamera
{
	Write-Output "InstallWindowsCamera"
	Get-AppxPackage -AllUsers "Microsoft.WindowsCamera" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
# Uninstall Windows Camera
Function UninstallWindowsCamera
{
	Write-Output "UninstallWindowsCamera"
	Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
}
# Install Windows Calculator
Function InstallWindowsCalculator
{
	Write-Output "InstallWindowsCalculator"
	Get-AppxPackage -AllUsers "Microsoft.WindowsCalculator" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
}
# Uninstall Windows Calculator
Function UninstallWindowsCalculator
{
	Write-Output "UninstallWindowsCalculator"
	Get-AppxPackage "Microsoft.WindowsCalculator" | Remove-AppxPackage
}
# Disable Xbox features - Not applicable to Server
Function DisableXboxFeatures
{
	Write-Output "DisableXboxFeatures"
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 | Out-Null
}
# Enable Xbox features - Not applicable to Server
Function EnableXboxFeatures
{
	Write-Output "EnableXboxFeatures"
	Get-AppxPackage -AllUsers "Microsoft.XboxApp" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxIdentityProvider" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxSpeechToTextOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGameOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.XboxGamingOverlay" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.Xbox.TCUI" | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 1 | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -ErrorAction SilentlyContinue | Out-Null
}
# Hide Desktop icon In This PC - The icon remains in personal folders and open/save dialogs
Function HideDesktopInThisPC
{
	Write-Output "HideDesktopInThisPC "
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Show Desktop icon in This PC
Function ShowDesktopInThisPC
{
	Write-Output "ShowDesktopInThisPC"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" | Out-Null
	}
}
# Hide Documents icon In This PC - The icon remains in personal folders and open/save dialogs
Function HideDocumentsInThisPC
{
	Write-Output "HideDocumentsInThisPC"
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Show Documents icon in This PC
Function ShowDocumentsInThisPC
{
	Write-Output "ShowDocumentsInThisPC "
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" | Out-Null
	}
}
# Hide Downloads icon In This PC - The icon remains in personal folders and open/save dialogs
Function HideDownloadsInThisPC
{
	Write-Output "HideDownloadsInThisPC"
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Show Downloads icon in This PC
Function ShowDownloadsInThisPC
{
	Write-Output "ShowDownloadsInThisPC "
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" | Out-Null
	}
}
# Hide Music icon In This PC - The icon remains in personal folders and open/save dialogs
Function HideMusicInThisPC
{
	Write-Output "HideMusicInThisPC "
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Show Music icon in This PC
Function ShowMusicInThisPC
{
	Write-Output "ShowMusicInThisPC"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" | Out-Null
	}
}
# Hide Pictures icon In This PC - The icon remains in personal folders and open/save dialogs
Function HidePicturesInThisPC
{
	Write-Output "HidePicturesInThisPC"
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Show Pictures icon in This PC
Function ShowPicturesInThisPC
{
	Write-Output "ShowPicturesInThisPC"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" | Out-Null
	}
}
# Hide Videos icon In This PC - The icon remains in personal folders and open/save dialogs
Function HideVideosInThisPC
{
	Write-Output "HideVideosInThisPC"
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue | Out-Null
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Show Videos icon in This PC
Function ShowVideosInThisPC 
{
	Write-Output "ShowVideosInThisPC"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" | Out-Null
	}
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" | Out-Null
	}
}
# Hide 3D Objects icon In This PC - The icon remains in personal folders and open/save dialogs
Function Hide3DObjectsInThisPC
{
	Write-Output "Hide3DObjectsInThisPC"
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Show 3D Objects icon in This PC
Function Show3DObjectsInThisPC
{
	Write-Output "Show3DObjectsInThisPC"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" | Out-Null
	}
}
# Hide Desktop icon In Explorer namespace - Hides the icon also In personal folders and open/save dialogs
Function HideDesktopInExplorer
{
	Write-Output "HideDesktopInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
}
# Show Desktop icon in Explorer namespace
Function ShowDesktopInExplorer
{
	Write-Output "ShowDesktopInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
}
# Hide Documents icon In Explorer namespace - Hides the icon also In personal folders and open/save dialogs
Function HideDocumentsInExplorer
{
	Write-Output "HideDocumentsInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
}
# Show Documents icon in Explorer namespace
Function ShowDocumentsInExplorer
{
	Write-Output "ShowDocumentsInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
}
# Hide Downloads icon In Explorer namespace - Hides the icon also In personal folders and open/save dialogs
Function HideDownloadsInExplorer
{
	Write-Output "HideDownloadsInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
}
# Show Downloads icon in Explorer namespace
Function ShowDownloadsInExplorer
{
	Write-Output "ShowDownloadsInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{7d83ee9b-2244-4e70-b1f5-5393042af1e4}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
}
# Hide Music icon In Explorer namespace - Hides the icon also In personal folders and open/save dialogs
Function HideMusicInExplorer
{
	Write-Output "HideMusicInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
}
# Show Music icon in Explorer namespace
Function ShowMusicInExplorer
{
	Write-Output "ShowMusicInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
}
# Hide Pictures icon In Explorer namespace - Hides the icon also In personal folders and open/save dialogs
Function HidePicturesInExplorer
{
	Write-Output "HidePicturesInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
}
# Show Pictures icon in Explorer namespace
Function ShowPicturesInExplorer
{
	Write-Output "ShowPicturesInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
}
# Hide Videos icon In Explorer namespace - Hides the icon also In personal folders and open/save dialogs
Function HideVideosInExplorer
{
	Write-Output "HideVideosInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
}
# Show Videos icon in Explorer namespace
Function ShowVideosInExplorer
{
	Write-Output "ShowVideosInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show" | Out-Null
}
# Hide 3D Objects icon In Explorer namespace - Hides the icon also In personal folders and open/save dialogs
Function Hide3DObjectsInExplorer
{
	Write-Output "Hide3DObjectsInExplorer"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
		New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide" | Out-Null
}
# Show 3D Objects icon in Explorer namespace
Function Show3DObjectsInExplorer
{
	Write-Output "Show3DObjectsInExplorer"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -ErrorAction SilentlyContinue | Out-Null
}
# Hide Network icon In Explorer namespace - Hides the icon also In personal folders and open/save dialogs
Function HideNetworkInExplorer
{
	Write-Output "HideNetworkInExplorer"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 1 | Out-Null
}
# Show Network icon in Explorer namespace
Function ShowNetworkInExplorer
{
	Write-Output "ShowNetworkInExplorer"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -ErrorAction SilentlyContinue | Out-Null
}
# Hide Recycle Bin shortcut In desktop
Function HideRecycleBinOnDesktop
{
	Write-Output "HideRecycleBinOnDesktop"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Type DWord -Value 1 | Out-Null
}

# Show Recycle Bin shortcut on desktop
Function ShowRecycleBinOnDesktop
{
	Write-Output "ShowRecycleBinOnDesktop"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -ErrorAction SilentlyContinue | Out-Null
}

# Show This PC shortcut on desktop
Function ShowThisPCOnDesktop
{
	Write-Output "ShowThisPCOnDesktop"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0 | Out-Null
}

# Hide This PC shortcut In desktop
Function HideThisPCOnDesktop
{
	Write-Output "HideThisPCOnDesktop"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -ErrorAction SilentlyContinue | Out-Null
}

# Show User Folder shortcut on desktop
Function ShowUserFolderOnDesktop
{
	Write-Output "ShowUserFolderOnDesktop"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0 | Out-Null
}

# Hide User Folder shortcut In desktop
Function HideUserFolderOnDesktop
{
	Write-Output "HideUserFolderOnDesktop"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -ErrorAction SilentlyContinue | Out-Null
}

# Show Control panel shortcut on desktop
Function ShowControlPanelOnDesktop
{
	Write-Output "ShowControlPanelOnDesktop"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Type DWord -Value 0 | Out-Null
}

# Hide Control panel shortcut In desktop
Function HideControlPanelOnDesktop
{
	Write-Output "HideControlPanelOnDesktop"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -ErrorAction SilentlyContinue | Out-Null
}

# Show Network shortcut on desktop
Function ShowNetworkOnDesktop
{
	Write-Output "ShowNetworkOnDesktop"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" )) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"  -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" )) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Type DWord -Value 0 | Out-Null
}
# Hide Network shortcut In desktop
Function HideNetworkOnDesktop
{
	Write-Output "HideNetworkOnDesktop"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -ErrorAction SilentlyContinue | Out-Null
}

# Hide 'Include in library' context menu item
Function HideIncludeInLibraryMenu
{
	Write-Output "HideIncludeInLibraryMenu"
	Remove-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue | Out-Null
}
# Show 'Include in library' context menu item
Function ShowIncludeInLibraryMenu
{
	Write-Output "ShowIncludeInLibraryMenu"
	New-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -Name "(Default)" -Type String -Value "{3dad6c5d-2167-4cae-9914-f99e41c12cfa}" | Out-Null
}
# Hide 'Give access to' context menu item.
Function HideGiveAccessToMenu
{
	Write-Output "HideGiveAccessToMenu"
	Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue

}
# Show 'Give access to' context menu item.
Function ShowGiveAccessToMenu
{
	Write-Output "ShowGiveAccessToMenu"
	New-Item -Path "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" | Out-Null
	New-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" | Out-Null
	New-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" | Out-Null
	New-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -Name "(Default)" -Type String -Value "{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}" | Out-Null
}
# Hide 'Share' context menu item.
Function HideShareMenu
{
	Write-Output "HideShareMenu"
	Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue | Out-Null
}
# Show 'Share' context menu item. Applicable since 1709
Function ShowShareMenu
{
	Write-Output "ShowShareMenu"
	New-Item -Path "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -Name "(Default)" -Type String -Value "{e2bf9676-5f8f-435c-97eb-11607a5bedf7}" | Out-Null
}
# Show full directory path in Explorer title bar
Function ShowExplorerTitleFullPath
{
	Write-Output "ShowExplorerTitleFullPath"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -Type DWord -Value 1 | Out-Null
}
# Hide full directory path in Explorer title bar, only directory name will be shown
Function HideExplorerTitleFullPath
{
	Write-Output "HideExplorerTitleFullPath"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -ErrorAction SilentlyContinue | Out-Null
}
# Show known file extensions
Function ShowKnownExtensions
{
	Write-Output "ShowKnownExtensions"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0 | Out-Null
}
# Hide known file extensions
Function HideKnownExtensions
{
	Write-Output "HideKnownExtensions"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 1 | Out-Null
}
# Show hidden files
Function ShowHiddenFiles
{
	Write-Output "ShowHiddenFiles"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 1 | Out-Null
}
# Hide hidden files
Function HideHiddenFiles
{
	Write-Output "Hiding hidden files..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Type DWord -Value 2 | Out-Null
}
# Show protected operating system files
Function ShowSuperHiddenFiles
{
	Write-Output "ShowSuperHiddenFiles"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 1 | Out-Null
}
# Hide protected operating system files
Function HideSuperHiddenFiles
{
	Write-Output "HideSuperHiddenFiles"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSuperHidden" -Type DWord -Value 0 | Out-Null
}
# Show empty drives (with no media)
Function ShowEmptyDrives
{
	Write-Output "ShowEmptyDrives"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -Type DWord -Value 0 | Out-Null
}
# Hide empty drives (with no media)
Function HideEmptyDrives
{
	Write-Output "HideEmptyDrives"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -ErrorAction SilentlyContinue | Out-Null
}
# Show folder merge conflicts
Function ShowFolderMergeConflicts
{
	Write-Output "ShowFolderMergeConflicts"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -Type DWord -Value 0 | Out-Null
}
# Hide folder merge conflicts
Function HideFolderMergeConflicts
{
	Write-Output "HideFolderMergeConflicts"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideMergeConflicts" -ErrorAction SilentlyContinue | Out-Null
}
# Enable Explorer navigation pane expanding to current folder
Function EnableNavPaneExpand
{
	Write-Output "EnableNavPaneExpand"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value 1 | Out-Null
}
# Disable Explorer navigation pane expanding to current folder
Function DisableNavPaneExpand
{
	Write-Output "DisableNavPaneExpand"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -ErrorAction SilentlyContinue | Out-Null
}
# Show all folders in Explorer navigation pane
Function ShowNavPaneAllFolders
{
	Write-Output "ShowNavPaneAllFolders"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -Type DWord -Value 1 | Out-Null
}
# Hide all folders from Explorer navigation pane except the basic ones (Quick access, OneDrive, This PC, Network), some of which can be disabled using other tweaks
Function HideNavPaneAllFolders
{
	Write-Output "HideNavPaneAllFolders"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -ErrorAction SilentlyContinue | Out-Null
}
# Show Libraries in Explorer navigation pane
Function ShowNavPaneLibraries
{
	Write-Output "ShowNavPaneLibraries"
	If (!(Test-Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}")) {
		New-Item -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -Type DWord -Value 1 | Out-Null
}
# Hide Libraries from Explorer navigation pane
Function HideNavPaneLibraries
{
	Write-Output "HideNavPaneLibraries"
	Remove-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{031E4825-7B94-4dc3-B131-E946B44C8DD5}" -Name "System.IsPinnedToNameSpaceTree" -ErrorAction SilentlyContinue | Out-Null
}
# Enable launching folder windows in a separate process
Function EnableFldrSeparateProcess
{
	Write-Output "EnableFldrSeparateProcess"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 1 | Out-Null
}
# Disable launching folder windows in a separate process
Function DisableFldrSeparateProcess
{
	Write-Output "DisableFldrSeparateProcess"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SeparateProcess" -Type DWord -Value 0 | Out-Null
}
# Enable restoring previous folder windows at logon
Function EnableRestoreFldrWindow
{
	Write-Output "EnableRestoreFldrWindows"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -Type DWord -Value 1 | Out-Null
}
# Disable restoring previous folder windows at logon
Function DisableRestoreFldrWindow
{
	Write-Output "DisableRestoreFldrWindows"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "PersistBrowsers" -ErrorAction SilentlyContinue | Out-Null
}
# Show coloring of encrypted or compressed NTFS files (green for encrypted, blue for compressed)
Function ShowEncCompFilesColor
{
	Write-Output "ShowEncCompFilesColor"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -Type DWord -Value 1 | Out-Null
}
# Hide coloring of encrypted or compressed NTFS files
Function HideEncCompFilesColor
{
	Write-Output "HideEncCompFilesColor"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Sharing Wizard
Function DisableSharingWizard
{
	Write-Output "DisableSharingWizard"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Type DWord -Value 0 | Out-Null
}
# Enable Sharing Wizard
Function EnableSharingWizard
{
	Write-Output "EnableSharingWizard"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -ErrorAction SilentlyContinue | Out-Null
}
# Hide item selection checkboxes
Function HideSelectCheckboxes
{
	Write-Output "HideSelectCheckboxes"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 0 | Out-Null
}
# Show item selection checkboxes
Function ShowSelectCheckboxes
{
	Write-Output "ShowSelectCheckboxes"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AutoCheckSelect" -Type DWord -Value 1 | Out-Null
}
# Hide sync provider notifications
Function HideSyncNotifications
{
	Write-Output "HideSyncNotifications"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0 | Out-Null
}
# Show sync provider notifications
Function ShowSyncNotifications
{
	Write-Output "ShowSyncNotifications"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value 1 | Out-Null
}
# Hide recently and frequently used item shortcuts in Explorer
Function HideRecentShortcuts
{
	Write-Output "HideRecentShortcuts"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Type DWord -Value 0 | Out-Null
}
# Show recently and frequently used item shortcuts in Explorer
Function ShowRecentShortcuts
{
	Write-Output "ShowRecentShortcuts"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -ErrorAction SilentlyContinue | Out-Null
}
# Change default Explorer view to This PC
Function SetExplorerThisPC
{
	Write-Output "SetExplorerThisPC"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1 | Out-Null
}
# Change default Explorer view to Quick Access
Function SetExplorerQuickAccess
{
	Write-Output "SetExplorerQuickAccess"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -ErrorAction SilentlyContinue | Out-Null
}
# Hide Quick Access from Explorer navigation pane
Function HideQuickAccess
{
	Write-Output "HideQuickAccess"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -Type DWord -Value 1 | Out-Null
}
# Show Quick Access in Explorer navigation pane
Function ShowQuickAccess
{
	Write-Output "ShowQuickAccess"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -ErrorAction SilentlyContinue | Out-Null
}
# Hide all icons from desktop
Function HideDesktopIcons
{
	Write-Output "HideDesktopIcons"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 1 | Out-Null
}
# Show all icons on desktop
Function ShowDesktopIcons
{
	Write-Output "ShowDesktopIcons"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideIcons" -Value 0 | Out-Null
}
# Show Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
Function ShowBuildNumberOnDesktop
{
	Write-Output "ShowBuildNumberOnDesktop"
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 1 | Out-Null
}
# Remove Windows build number and Windows edition (Home/Pro/Enterprise) from bottom right of desktop
Function HideBuildNumberOnDesktop
{
	Write-Output "HideBuildNumberOnDesktop"
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "PaintDesktopVersion" -Type DWord -Value 0 | Out-Null
}
# Disable thumbnails, show only file extension icons
Function DisableThumbnails
{
	Write-Output "DisableThumbnails"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 1 | Out-Null
}
# Enable thumbnails
Function EnableThumbnails
{
	Write-Output "EnableThumbnails"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Type DWord -Value 0 | Out-Null
}
# Disable creation of thumbnail cache files
Function DisableThumbnailCache
{
	Write-Output "DisableThumbnailCache"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Type DWord -Value 1 | Out-Null
}
# Enable creation of thumbnail cache files
Function EnableThumbnailCache
{
	Write-Output "EnableThumbnailCache"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -ErrorAction SilentlyContinue | Out-Null
}
# Disable creation of Thumbs.db thumbnail cache files on network folders
Function DisableThumbsDBOnNetwork
{
	Write-Output "DisableThumbsDBOnNetwork"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1 | Out-Null
}
# Enable creation of Thumbs.db thumbnail cache files on network folders
Function EnableThumbsDBOnNetwork
{
	Write-Output "EnableThumbsDBOnNetwork"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Action Center (Notification Center)
Function DisableActionCenter
{
	Write-Output "DisableActionCenter"
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0 | Out-Null
}
# Enable Action Center (Notification Center)
Function EnableActionCenter
{
	Write-Output "EnableActionCenter"
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Lock screen
Function DisableLockScreen
{
	Write-Output "DisableLockScreen"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1 | Out-Null
}
# Enable Lock screen
Function EnableLockScreen
{
	Write-Output "EnableLockScreen"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -ErrorAction SilentlyContinue | Out-Null
}
Function HideNetworkFromLockScreen
{
	Write-Output "HideNetworkFromLockScreen"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -Type DWord -Value 1 | Out-Null
}
# Show network options on lock screen
Function ShowNetworkOnLockScreen
{
	Write-Output "ShowNetworkOnLockScreen"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue | Out-Null
}
# Hide shutdown options from Lock Screen
Function HideShutdownOnLockScreen
{
	Write-Output "HideShutdownOnLockScreen"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 0 | Out-Null
}
# Show shutdown options on lock screen
Function ShowShutdownOnLockScreen
{
	Write-Output "ShowShutdownOnLockScreen"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -Type DWord -Value 1 | Out-Null
}
# Disable Lock screen Blur
Function DisableLockScreenBlur
{
	Write-Output "DisableLockScreenBlur"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -Type DWord -Value 1 | Out-Null
}
# Enable Lock screen Blur
Function EnableLockScreenBlur
{
	Write-Output "EnableLockScreenBlur"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableAcrylicBackgroundOnLogon" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Aero Shake (minimizing other windows when one is dragged by mouse and shaken)
Function DisableAeroShake
{
	Write-Output "DisableAeroShake"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -Type DWord -Value 1 | Out-Null
}
# Enable Aero Shake
Function EnableAeroShake
{
	Write-Output "EnableAeroShake"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisallowShaking" -ErrorAction SilentlyContinue | Out-Null
}
# Disable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
Function DisableAccessibilityKeys
{
	Write-Output "DisableAccessibilityKeys"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "506" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "58" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "122" | Out-Null
}
# Enable accessibility keys prompts (Sticky keys, Toggle keys, Filter keys)
Function EnableAccessibilityKeys
{
	Write-Output "EnableAccessibilityKeys"
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Type String -Value "510" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Type String -Value "62" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Type String -Value "126" | Out-Null
}
# Show file operations details
Function ShowFileOperationsDetails
{
	Write-Output "ShowFileOperationsDetails"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1 | Out-Null
}
# Hide file operations details
Function HideFileOperationsDetails
{
	Write-Output "HideFileOperationsDetails"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -ErrorAction SilentlyContinue | Out-Null
}
# Enable file delete confirmation dialog
Function EnableFileDeleteConfirm
{
	Write-Output "EnableFileDeleteConfirm"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1 | Out-Null
}
# Disable file delete confirmation dialog
Function DisableFileDeleteConfirm
{
	Write-Output "DisableFileDeleteConfirm"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue | Out-Null
}
# Hide Taskbar Search icon / box
Function HideTaskbarSearch
{
	Write-Output "HideTaskbarSearch"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0 | Out-Null
}
# Show Taskbar Search icon
Function ShowTaskbarSearchIcon
{
	Write-Output "ShowTaskbarSearchIcon"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 1 | Out-Null
}
# Show Taskbar Search box
Function ShowTaskbarSearchBox
{
	Write-Output "ShowTaskbarSearchBox"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 2 | Out-Null
}
# Hide Task View button
Function HideTaskView
{
	Write-Output "HideTaskView"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0 | Out-Null
}
# Show Task View button
Function ShowTaskView
{
	Write-Output "ShowTaskView"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue | Out-Null
}
# Show small icons in taskbar
Function SmallTaskbarIcons
{
	Write-Output "SmallTaskbarIcons"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -Type DWord -Value 1 | Out-Null
}
# Show large icons in taskbar
Function LargeTaskbarIcons
{
	Write-Output "LargeTaskbarIcons"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue | Out-Null
}
# Set taskbar buttons to show labels and combine when taskbar is full
Function SetTaskbarCombineWhenFull
{
	Write-Output "SetTaskbarCombineWhenFull"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 1 | Out-Null
}
# Set taskbar buttons to show labels and never combine
Function SetTaskbarCombineNever
{
	Write-Output "SetTaskbarCombineNever"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -Type DWord -Value 2 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -Type DWord -Value 2 | Out-Null
}
# Set taskbar buttons to always combine and hide labels
Function SetTaskbarCombineAlways
{
	Write-Output "SetTaskbarCombineAlways"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "MMTaskbarGlomLevel" -ErrorAction SilentlyContinue | Out-Null
}
# Hide Taskbar People icon
Function HideTaskbarPeopleIcon
{
	Write-Output "HideTaskbarPeopleIcon"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0 | Out-Null
}
# Show Taskbar People icon
Function ShowTaskbarPeopleIcon
{
	Write-Output "ShowTaskbarPeopleIcon"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -ErrorAction SilentlyContinue | Out-Null
}
# Show all tray icons
Function ShowTrayIcons
{
	Write-Output "ShowTrayIcons"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -Type DWord -Value 1 | Out-Null
}
# Hide tray icons as needed
Function HideTrayIcons
{
	Write-Output "HideTrayIcons"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutoTrayNotify" -ErrorAction SilentlyContinue | Out-Null
}
# Show seconds in taskbar
Function ShowSecondsInTaskbar
{
	Write-Output "ShowSecondsInTaskbar"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1 | Out-Null
}
# Hide seconds from taskbar
Function HideSecondsInTaskbar
{
	Write-Output "HideSecondsInTaskbar"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -ErrorAction SilentlyContinue | Out-Null
}
# Disable search for app in store for unknown extensions
Function DisableSearchAppInStore
{
	Write-Output "DisableSearchAppInStore"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1 | Out-Null
}
# Enable search for app in store for unknown extensions
Function EnableSearchAppInStore
{
	Write-Output "EnableSearchAppInStore"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue | Out-Null
}
# Disable 'How do you want to open this file?' prompt
Function DisableNewAppPrompt
{
	Write-Output "DisableNewAppPrompt"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -Type DWord -Value 1 | Out-Null
}
# Enable 'How do you want to open this file?' prompt
Function EnableNewAppPrompt
{
	Write-Output "EnableNewAppPrompt"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue | Out-Null
}
# Hide 'Recently added' list from the Start Menu
Function HideRecentlyAddedApps
{
	Write-Output "HideRecentlyAddedApps"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Type DWord -Value 1 | Out-Null
}
# Show 'Recently added' list in the Start Menu
Function ShowRecentlyAddedApps
{
	Write-Output "ShowRecentlyAddedApps"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -ErrorAction SilentlyContinue | Out-Null
}
# Hide 'Most used' apps list from the Start Menu
Function HideMostUsedApps
{
	Write-Output "HideMostUsedApps"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -Type DWord -Value 1 | Out-Null
}
# Show 'Most used' apps list in the Start Menu
Function ShowMostUsedApps
{
	Write-Output "ShowMostUsedApps"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList" -ErrorAction SilentlyContinue | Out-Null
}
# Set PowerShell instead of Command prompt in Start Button context menu (Win+X)
Function SetWinXMenuPowerShell
{
	Write-Output "SetWinXMenuPowerShell"
	If ([System.Environment]::OSVersion.Version.Build -le 14393) {
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Type DWord -Value 0 | Out-Null
	} Else {
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -ErrorAction SilentlyContinue | Out-Null
	}
}
# Set Command prompt instead of PowerShell in Start Button context menu (Win+X)
Function SetWinXMenuCmd
{
	Write-Output "SetWinXMenuCmd"
	If ([System.Environment]::OSVersion.Version.Build -le 14393) {
		Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -ErrorAction SilentlyContinue | Out-Null
	} Else {
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DontUsePowerShellOnWinX" -Type DWord -Value 1 | Out-Null
	}
}
# Set Control Panel view to Small icons (Classic)
Function SetControlPanelSmallIcons
{
	Write-Output "SetControlPanelSmallIcons"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 1 | Out-Null
}
# Set Control Panel view to Large icons (Classic)
Function SetControlPanelLargeIcons
{
	Write-Output "SetControlPanelLargeIcons"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -Type DWord -Value 0 | Out-Null
}
# Set Control Panel view to categories
Function SetControlPanelCategories
{
	Write-Output "SetControlPanelCategories"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "StartupPage" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" -Name "AllItemsIconView" -ErrorAction SilentlyContinue | Out-Null
}
# Disable adding '- shortcut' to shortcut name
Function DisableShortcutInName
{
	Write-Output "DisableShortcutInName"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -Type Binary -Value ([byte[]](0,0,0,0)) | Out-Null
}
# Enable adding '- shortcut' to shortcut name
Function EnableShortcutInName
{
	Write-Output "EnableShortcutInName"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "link" -ErrorAction SilentlyContinue | Out-Null
}
# Hide shortcut icon arrow
Function HideShortcutArrow
{
	Write-Output "HideShortcutArrow"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -Type String -Value "%SystemRoot%\System32\imageres.dll,-1015" | Out-Null
}
# Show shortcut icon arrow
Function ShowShortcutArrow
{
	Write-Output "ShowShortcutArrow"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" -Name "29" -ErrorAction SilentlyContinue | Out-Null
}
# Adjusts visual effects for performance - Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance
{
	Write-Output "SetVisualFXPerformance"
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0)) | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0 | Out-Null
}
# Adjusts visual effects for appearance
Function SetVisualFXAppearance
{
	Write-Output "SetVisualFXAppearance"
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 400 | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](158,30,7,128,18,0,0,0)) | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 1 | Out-Null
}
# Enable window title bar color according to prevalent background color
Function EnableTitleBarColor
{
	Write-Output "EnableTitleBarColor"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 1 | Out-Null
}
# Disable window title bar color
Function DisableTitleBarColor
{
	Write-Output "DisableTitleBarColor"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorPrevalence" -Type DWord -Value 0 | Out-Null
}
# Set Dark Mode for Applications
Function SetAppsDarkMode
{
	Write-Output "SetAppsDarkMode"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 0 | Out-Null
}
# Set Light Mode for Applications
Function SetAppsLightMode
{
	Write-Output "SetAppsLightMode"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Type DWord -Value 1 | Out-Null
}
# Set Light Mode for System - Applicable since 1903
Function SetSystemLightMode
{
	Write-Output "SetSystemLightMode"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 1 | Out-Null
}
# Set Dark Mode for System - Applicable since 1903
Function SetSystemDarkMode
{
	Write-Output "SetSystemDarkMode"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Type DWord -Value 0 | Out-Null
}
# Add secondary en-US keyboard
Function AddENKeyboard
{
	Write-Output "AddENKeyboard"
	$langs = Get-WinUserLanguageList
	$langs.Add("en-US")
	Set-WinUserLanguageList $langs -Force
}
# Remove secondary en-US keyboard
Function RemoveENKeyboard
{
	Write-Output "RemoveENKeyboard"
	$langs = Get-WinUserLanguageList
	Set-WinUserLanguageList ($langs | Where-Object {$_.LanguageTag -ne "en-US"}) -Force | Out-Null
}
# Enable NumLock after startup
Function EnableNumlock
{
	Write-Output "EnableNumlock"
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650 | Out-Null
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}
# Disable NumLock after startup
Function DisableNumlock
{
	Write-Output "DisableNumlock"
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483648 | Out-Null
	Add-Type -AssemblyName System.Windows.Forms
	If ([System.Windows.Forms.Control]::IsKeyLocked('NumLock')) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
}
# Disable enhanced pointer precision
Function DisableEnhPointerPrecision
{
	Write-Output "DisableEnhPointerPrecision"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "0" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "0" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "0" | Out-Null
}
# Enable enhanced pointer precision
Function EnableEnhPointerPrecision
{
	Write-Output "EnableEnhPointerPrecision"
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type String -Value "1" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type String -Value "6" | Out-Null
	Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type String -Value "10" | Out-Null
}

# Disable playing Windows Startup sound
Function DisableStartupSound
{
	Write-Output "DisableStartupSound"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 1 | Out-Null
}
# Enable playing Windows Startup sound
Function EnableStartupSound
{
	Write-Output "EnableStartupSound"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Type DWord -Value 0 | Out-Null
}
# Enable verbose startup/shutdown status messages
Function EnableVerboseStatus
{
	Write-Output "EnableVerboseStatus"
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 1 | Out-Null
	} Else {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue | Out-Null
	}
}
# Disable verbose startup/shutdown status messages
Function DisableVerboseStatus
{
	Write-Output "DisableVerboseStatus"
	If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
		Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue | Out-Null
	} Else {
		Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type DWord -Value 0 | Out-Null
	}
}
# Disable F1 Help key in Explorer and on the Desktop
Function DisableF1HelpKey
{
	Write-Output "DisableF1HelpKey"
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
		New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -Type "String" -Value "" | Out-Null
	If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
		New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -Type "String" -Value "" | Out-Null
}
# Enable F1 Help key in Explorer and on the Desktop
Function EnableF1HelpKey
{
	Write-Output "EnableF1HelpKey"
	Remove-Item "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Disable offering of Malicious Software Removal Tool through Windows Update
Function DisableUpdateMSRT
{
	Write-Output "DisableUpdateMSRT"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 1 | Out-Null
}
# Enable offering of Malicious Software Removal Tool through Windows Update
Function EnableUpdateMSRT
{
	Write-Output "EnableUpdateMSRT"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue | Out-Null
}
# Disable offering of drivers through Windows Update
Function DisableUpdateDriver
{
	Write-Output "DisableUpdateDriver"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1 | Out-Null
}
# Enable offering of drivers through Windows Update
Function EnableUpdateDriver
{
	Write-Output "EnableUpdateDriver"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "SearchOrderConfig" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue | Out-Null
}
# Enable receiving updates for other Microsoft products via Windows Update
Function EnableUpdateMSProducts
{
	Write-Output "EnableUpdateMSProducts"
	(New-Object -ComObject Microsoft.Update.ServiceManager).AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null
}
# Disable receiving updates for other Microsoft products via Windows Update
Function DisableUpdateMSProducts
{
	Write-Output "DisableUpdateMSProducts"
	If ((New-Object -ComObject Microsoft.Update.ServiceManager).Services | Where-Object { $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d"}) {
		(New-Object -ComObject Microsoft.Update.ServiceManager).RemoveService("7971f918-a847-4430-9279-4a52d1efe18d") | Out-Null
	}
}
# Disable Windows Update automatic downloads
Function DisableUpdateAutoDownload
{
	Write-Output "DisableUpdateAutoDownload"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2 | Out-Null
}
# Enable Windows Update automatic downloads
Function EnableUpdateAutoDownload
{
	Write-Output "EnableUpdateAutoDownload"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue | Out-Null
}
# Disable nightly wake-up for Automatic Maintenance and Windows Updates
Function DisableMaintenanceWakeUp
{
	Write-Output "DisableMaintenanceWakeUp"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -Type DWord -Value 0 | Out-Null
}
# Enable nightly wake-up for Automatic Maintenance and Windows Updates
Function EnableMaintenanceWakeUp
{
	Write-Output "EnableMaintenanceWakeUp"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Automatic Restart Sign-on
Function DisableAutoRestartSignOn
{
	Write-Output "DisableAutoRestartSignOn"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Type DWord -Value 1 | Out-Null
}
# Enable Automatic Restart Sign-on
Function EnableAutoRestartSignOn
{
	Write-Output "EnableAutoRestartSignOn"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Shared Experiences
Function DisableSharedExperiences
{
	Write-Output "DisableSharedExperiences"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 0 | Out-Null
}
# Enable Shared Experiences
Function EnableSharedExperiences
{
	Write-Output "EnableSharedExperiences"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -Type DWord -Value 1 | Out-Null
}
# Enable Clipboard History
Function EnableClipboardHistory
{
	Write-Output "EnableClipboardHistory"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1 | Out-Null
}
# Disable Clipboard History
Function DisableClipboardHistory
{
	Write-Output "DisableClipboardHistory"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Autoplay
Function DisableAutoplay
{
	Write-Output "DisableAutoplay"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1 | Out-Null
}
# Enable Autoplay
Function EnableAutoplay
{
	Write-Output "EnableAutoplay"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 0 | Out-Null
}
# Disable Autorun for all drives
Function DisableAutorun
{
	Write-Output "DisableAutorun"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255 | Out-Null
}
# Enable Autorun for removable drives
Function EnableAutorun
{
	Write-Output "EnableAutorun"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue | Out-Null
}
# Disable System Restore for system drive - Not applicable to Server
Function DisableRestorePoints
{
	Write-Output "DisableRestorePoints"
	Disable-ComputerRestore -Drive "$env:SYSTEMDRIVE"
}
# Enable System Restore for system drive - Not applicable to Server
Function EnableRestorePoints
{
	Write-Output "EnableRestorePoints"
	Enable-ComputerRestore -Drive "$env:SYSTEMDRIVE"
}
# Enable Storage Sense
Function EnableStorageSense
{
	Write-Output "EnableStorageSense"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "StoragePoliciesNotified" -Type DWord -Value 1 | Out-Null
}
# Disable Storage Sense
Function DisableStorageSense
{
	Write-Output "DisableStorageSense"
	Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue | Out-Null
}
# Disable scheduled defragmentation task
Function DisableDefragmentation
{
	Write-Output "DisableDefragmentation."
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
# Enable scheduled defragmentation task
Function EnableDefragmentation
{
	Write-Output "EnableDefragmentation"
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}
# Stop and disable Superfetch service
Function DisableSuperfetch
{
	Write-Output "DisableSuperfetch"
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
}
# Start and enable Superfetch service
Function EnableSuperfetch
{
	Write-Output "EnableSuperfetch"
	Set-Service "SysMain" -StartupType Automatic
	Start-Service "SysMain" -WarningAction SilentlyContinue
}
# Stop and disable Windows Search indexing service
Function DisableIndexing
{
	Write-Output "DisableIndexing"
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
}
# Start and enable Windows Search indexing service
Function EnableIndexing
{
	Write-Output "EnableIndexing"
	Set-Service "WSearch" -StartupType Automatic
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name "DelayedAutoStart" -Type DWord -Value 1 | Out-Null
	Start-Service "WSearch" -WarningAction SilentlyContinue
}
# Disable Recycle Bin - Files will be permanently deleted without placing into Recycle Bin
Function DisableRecycleBin
{
	Write-Output "DisableRecycleBin"
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecycleFiles" -Type DWord -Value 1 | Out-Null
}
# Enable Recycle Bin
Function EnableRecycleBin
{
	Write-Output "EnableRecycleBin"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecycleFiles" -ErrorAction SilentlyContinue | Out-Null
}
# Enable NTFS paths with length over 260 characters
Function EnableNTFSLongPaths
{
	Write-Output "EnableNTFSLongPaths"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 1 | Out-Null
}
# Disable NTFS paths with length over 260 characters
Function DisableNTFSLongPaths
{
	Write-Output "DisableNTFSLongPaths"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Type DWord -Value 0 | Out-Null
}
# Disable updating of NTFS last access timestamps
Function DisableNTFSLastAccess
{
	Write-Output "DisableNTFSLastAccess"
	# User Managed, Last Access Updates Disabled
	fsutil behavior set DisableLastAccess 1 | Out-Null
}
# Enable updating of NTFS last access timestamps
Function EnableNTFSLastAccess
{
	Write-Output "EnableNTFSLastAccess"
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		# System Managed, Last Access Updates Enabled
		fsutil behavior set DisableLastAccess 2 | Out-Null
	} Else {
		# Last Access Updates Enabled
		fsutil behavior set DisableLastAccess 0 | Out-Null
	}
}
# Set BIOS time to UTC
Function SetBIOSTimeUTC
{
	Write-Output "SetBIOSTimeUTC"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1 | Out-Null
}
# Set BIOS time to local time
Function SetBIOSTimeLocal
{
	Write-Output "SetBIOSTimeLocal"
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue | Out-Null
}
# Enable Hibernation
Function EnableHibernation
{
	Write-Output "EnableHibernation"
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 1 | Out-Null
	powercfg /HIBERNATE ON 2>&1 | Out-Null
}
# Disable Hibernation
Function DisableHibernation
{
	Write-Output "DisableHibernation"
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type DWord -Value 0 | Out-Null
	powercfg /HIBERNATE OFF 2>&1 | Out-Null
}
# Disable Sleep start menu and keyboard button
Function DisableSleepButton
{
	Write-Output "DisableSleepButton"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 0 | Out-Null
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 0
}
# Enable Sleep start menu and keyboard button
Function EnableSleepButton
{
	Write-Output "EnableSleepButton"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Type DWord -Value 1 | Out-Null
	powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
	powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_BUTTONS SBUTTONACTION 1
}
# Disable display and sleep mode timeouts
Function DisableSleepTimeout
{
	Write-Output "DisableSleepTimeout"
	powercfg /X monitor-timeout-ac 0
	powercfg /X monitor-timeout-dc 0
	powercfg /X standby-timeout-ac 0
	powercfg /X standby-timeout-dc 0
}
# Enable display and sleep mode timeouts
Function EnableSleepTimeout
{
	Write-Output "EnableSleepTimeout"
	powercfg /X monitor-timeout-ac 10
	powercfg /X monitor-timeout-dc 5
	powercfg /X standby-timeout-ac 30
	powercfg /X standby-timeout-dc 15
}
# Disable Fast Startup
Function DisableFastStartup
{
	Write-Output "DisableFastStartup"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0 | Out-Null
}
# Enable Fast Startup
Function EnableFastStartup
{
	Write-Output "EnableFastStartup"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1 | Out-Null
}
# Disable automatic reboot on crash (BSOD)
Function DisableAutoRebootOnCrash
{
	Write-Output "DisableAutoRebootOnCrash"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 0 | Out-Null
}
# Enable automatic reboot on crash (BSOD)
Function EnableAutoRebootOnCrash
{
	Write-Output "EnableAutoRebootOnCrash"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 1 | Out-Null
}
# Set current network profile to private (allow file sharing, device discovery, etc.)
Function SetCurrentNetworkPrivate
{
	Write-Output "SetCurrentNetworkPrivate"
	Set-NetConnectionProfile -NetworkCategory Private
}
# Set current network profile to public (deny file sharing, device discovery, etc.)
Function SetCurrentNetworkPublic
{
	Write-Output "SetCurrentNetworkPublic"
	Set-NetConnectionProfile -NetworkCategory Public
}
# Set unknown networks profile to private (allow file sharing, device discovery, etc.)
Function SetUnknownNetworksPrivate
{
	Write-Output "SetUnknownNetworksPrivate"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -Type DWord -Value 1 | Out-Null
}
# Set unknown networks profile to public (deny file sharing, device discovery, etc.)
Function SetUnknownNetworksPublic
{
	Write-Output "SetUnknownNetworksPublic"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\010103000F0000F0010000000F0000F0C967A3643C3AD745950DA7859209176EF5B87C875FA20DF21951640E807D7C24" -Name "Category" -ErrorAction SilentlyContinue | Out-Null
}
# Disable automatic installation of network devices
Function DisableNetDevicesAutoInst
{
	Write-Output "DisableNetDevicesAutoInst"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -Type DWord -Value 0 | Out-Null
}
# Enable automatic installation of network devices
Function EnableNetDevicesAutoInst
{
	Write-Output "EnableNetDevicesAutoInst"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private" -Name "AutoSetup" -ErrorAction SilentlyContinue | Out-Null
}
# Disable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function DisableSMB1
{
	Write-Output "DisableSMB1"
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}
# Enable obsolete SMB 1.0 protocol - Disabled by default since 1709
Function EnableSMB1
{
	Write-Output "EnableSMB1"
	Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}
# Disable SMB Server - Completely disables file and printer sharing, but leaves the system able to connect to another SMB server as a client
Function DisableSMBServer
{
	Write-Output "DisableSMBServer"
	Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
	Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}
# Enable SMB Server
Function EnableSMBServer
{
	Write-Output "EnableSMBServer"
	Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_server"
}
# Disable NetBIOS over TCP/IP on all currently installed network interfaces
Function DisableNetBIOS
{
	Write-Output "DisableNetBIOS"
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 2 | Out-Null
}
# Enable NetBIOS over TCP/IP on all currently installed network interfaces
Function EnableNetBIOS
{
	Write-Output "EnableNetBIOS"
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -Type DWord -Value 0 | Out-Null
}
# Disable Link-Local Multicast Name Resolution (LLMNR) protocol
Function DisableLLMNR
{
	Write-Output "DisableLLMNR"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0 | Out-Null
}
# Enable Link-Local Multicast Name Resolution (LLMNR) protocol
Function EnableLLMNR
{
	Write-Output "EnableLLMNR"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Local-Link Discovery Protocol (LLDP) for all installed network interfaces
Function DisableLLDP
{
	Write-Output "DisableLLDP"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"
}
# Enable Local-Link Discovery Protocol (LLDP) for all installed network interfaces
Function EnableLLDP
{
	Write-Output "EnableLLDP"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp"
}
# Disable Local-Link Topology Discovery (LLTD) for all installed network interfaces
Function DisableLLTD
{
	Write-Output "DisableLLTD"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
}
# Enable Local-Link Topology Discovery (LLTD) for all installed network interfaces
Function EnableLLTD
{
	Write-Output "EnableLLTD"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr"
}
# Disable Client for Microsoft Networks for all installed network interfaces
Function DisableMSNetClient
{
	Write-Output "DisableMSNetClient"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"
}
# Enable Client for Microsoft Networks for all installed network interfaces
Function EnableMSNetClient
{
	Write-Output "EnableMSNetClient"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient"
}
# Disable Quality of Service (QoS) packet scheduler for all installed network interfaces
Function DisableQoS
{
	Write-Output "DisableQoS"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
}
# Enable Quality of Service (QoS) packet scheduler for all installed network interfaces
Function EnableQoS
{
	Write-Output "EnableQoS"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer"
}
# Disable IPv4 stack for all installed network interfaces
Function DisableIPv4
{
	Write-Output "DisableIPv4"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip"
}
# Enable IPv4 stack for all installed network interfaces
Function EnableIPv4
{
	Write-Output "EnableIPv4"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip"
}
# Disable IPv6 stack for all installed network interfaces
Function DisableIPv6
{
	Write-Output "DisableIPv6"
	Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}
# Enable IPv6 stack for all installed network interfaces
Function EnableIPv6
{
	Write-Output "EnableIPv6"
	Enable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6"
}
# Disable Network Connectivity Status Indicator active test
Function DisableNCSIProbe
{
	Write-Output "DisableNCSIProbe"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1 | Out-Null
}
# Enable Network Connectivity Status Indicator active test
Function EnableNCSIProbe
{
	Write-Output "EnableNCSIProbe"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Internet Connection Sharing (e.g. mobile hotspot)
Function DisableConnectionSharing
{
	Write-Output "DisableConnectionSharing"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0 | Out-Null
}
# Enable Internet Connection Sharing (e.g. mobile hotspot)
Function EnableConnectionSharing
{
	Write-Output "EnableConnectionSharing"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function DisableRemoteAssistance
{
	Write-Output "DisableRemoteAssistance"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0 | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Remove-WindowsCapability -Online | Out-Null
}
# Enable Remote Assistance - Not applicable to Server (unless Remote Assistance is explicitly installed)
Function EnableRemoteAssistance
{
	Write-Output "EnableRemoteAssistance"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 1 | Out-Null
	Get-WindowsCapability -Online | Where-Object { $_.Name -like "App.Support.QuickAssist*" } | Add-WindowsCapability -Online | Out-Null
}
# Enable Remote Desktop
Function EnableRemoteDesktop
{
	Write-Output "EnableRemoteDesktop"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 0 | Out-Null
	Enable-NetFirewallRule -Name "RemoteDesktop*"
}
# Disable Remote Desktop
Function DisableRemoteDesktop
{
	Write-Output "DisableRemoteDesktop"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1 | Out-Null
	Disable-NetFirewallRule -Name "RemoteDesktop*"
}
# Lower UAC level (disabling it completely would break apps)
Function SetUACLow
{
	Write-Output "SetUACLow"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0 | Out-Null
}
# Raise UAC level
Function SetUACHigh
{
	Write-Output "SetUACHigh"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1 | Out-Null
}
# Enable sharing mapped drives between users
Function EnableSharingMappedDrives
{
	Write-Output "EnableSharingMappedDrives"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1 | Out-Null
}
# Disable sharing mapped drives between users
Function DisableSharingMappedDrives
{
	Write-Output "DisableSharingMappedDrives"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue | Out-Null
}
# Disable implicit administrative shares
Function DisableAdminShares
{
	Write-Output "DisableAdminShares"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0 | Out-Null
}
# Enable implicit administrative shares
Function EnableAdminShares
{
	Write-Output "EnableAdminShares"
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Firewall
Function DisableFirewall
{
	Write-Output "DisableFirewall"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -Type DWord -Value 0 | Out-Null
}
# Enable Firewall
Function EnableFirewall
{
	Write-Output "EnableFirewall"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue | Out-Null
}
# Hide Windows Defender SysTray icon
Function HideDefenderTrayIcon
{
	Write-Output "HideDefenderTrayIcon"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -Type DWord -Value 1 | Out-Null
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue | Out-Null
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063) {
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue | Out-Null
	}
}
# Show Windows Defender SysTray icon
Function ShowDefenderTrayIcon
{
	Write-Output "ShowDefenderTrayIcon"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" -Name "HideSystray" -ErrorAction SilentlyContinue | Out-Null
	If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -Type ExpandString -Value "`"%ProgramFiles%\Windows Defender\MSASCuiL.exe`"" | Out-Null
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 17134) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%ProgramFiles%\Windows Defender\MSASCuiL.exe" | Out-Null
	} ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17763) {
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -Type ExpandString -Value "%windir%\system32\SecurityHealthSystray.exe" | Out-Null
	}
}
# Disable Windows Defender Cloud
Function DisableDefenderCloud
{
	Write-Output "DisableDefenderCloud"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2 | Out-Null
}
# Enable Windows Defender Cloud
Function EnableDefenderCloud
{
	Write-Output "EnableDefenderCloud"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -ErrorAction SilentlyContinue | Out-Null
}
# Enable Controlled Folder Access (Defender Exploit Guard feature)
Function EnableCtrldFolderAccess
{
	Write-Output "EnableCtrldFolderAccess"
	Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue | Out-Null
}
# Disable Controlled Folder Access (Defender Exploit Guard feature)
Function DisableCtrldFolderAccess
{
	Write-Output "DisableCtrldFolderAccess"
	Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue | Out-Null
}
# Enable Windows Defender Application Guard
Function EnableDefenderAppGuard
{
	Write-Output "EnableDefenderAppGuard"
	Enable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
# Disable Windows Defender Application Guard
Function DisableDefenderAppGuard
{
	Write-Output "DisableDefenderAppGuard"
	Disable-WindowsOptionalFeature -online -FeatureName "Windows-Defender-ApplicationGuard" -NoRestart -WarningAction SilentlyContinue | Out-Null
}
# Hide Account Protection warning in Defender about not using a Microsoft account
Function HideAccountProtectionWarn
{
	Write-Output "HideAccountProtectionWarn"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows Security Health\State")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows Security Health\State" -Force | Out-Null
	}
	Set-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -Type DWord -Value 1 | Out-Null
}
# Show Account Protection warning in Defender
Function ShowAccountProtectionWarn
{
	Write-Output "ShowAccountProtectionWarn"
	Remove-ItemProperty "HKCU:\Software\Microsoft\Windows Security Health\State" -Name "AccountProtection_MicrosoftAccount_Disconnected" -ErrorAction SilentlyContinue | Out-Null
}
# Disable blocking of downloaded files
Function DisableDownloadBlocking
{
	Write-Output "DisableDownloadBlocking"
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type DWord -Value 1 | Out-Null
}
# Enable blocking of downloaded files
Function EnableDownloadBlocking
{
	Write-Output "EnableDownloadBlocking"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Windows Script Host (execution of *.vbs scripts and alike)
Function DisableScriptHost
{
	Write-Output "DisableScriptHost"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Type DWord -Value 0 | Out-Null
}
# Enable Windows Script Host
Function EnableScriptHost
{
	Write-Output "EnableScriptHost"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -ErrorAction SilentlyContinue | Out-Null
}
# Enable strong cryptography for old versions of .NET Framework (4.6 and newer have strong crypto enabled by default)
Function EnableDotNetStrongCrypto
{
	Write-output "EnableDotNetStrongCrypto"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1 | Out-Null
}
# Disable strong cryptography for old versions of .NET Framework
Function DisableDotNetStrongCrypto
{
	Write-output "DisableDotNetStrongCrypto"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue | Out-Null
}
# Enable F8 boot menu options
Function EnableF8BootMenu
{
	Write-Output "EnableF8BootMenu"
	bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null
}
# Disable F8 boot menu options
Function DisableF8BootMenu
{
	Write-Output "DisableF8BootMenu"
	bcdedit /set `{current`} BootMenuPolicy Standard | Out-Null
}
# Disable automatic recovery mode during boot
Function DisableBootRecovery
{
	Write-Output "DisableBootRecovery"
	bcdedit /set `{current`} BootStatusPolicy IgnoreAllFailures | Out-Null
}
# Enable automatic entering recovery mode during boot
Function EnableBootRecovery
{
	Write-Output "EnableBootRecovery"
	bcdedit /deletevalue `{current`} BootStatusPolicy | Out-Null
}
# Disable System Recovery and Factory reset
Function DisableRecoveryAndReset
{
	Write-Output "DisableRecoveryAndReset"
	reagentc /disable 2>&1 | Out-Null
}
# Enable System Recovery and Factory reset
Function EnableRecoveryAndReset
{
	Write-Output "EnableRecoveryAndReset"
	reagentc /enable 2>&1 | Out-Null
}
# Set Data Execution Prevention (DEP) policy to OptOut - Turn on DEP for all 32-bit applications except manually excluded. 64-bit applications have DEP always on.
Function SetDEPOptOut
{
	Write-Output "SetDEPOptOut"
	bcdedit /set `{current`} nx OptOut | Out-Null
}
# Set Data Execution Prevention (DEP) policy to OptIn - Turn on DEP only for essential 32-bit Windows executables and manually included applications. 64-bit applications have DEP always on.
Function SetDEPOptIn
{
	Write-Output "SetDEPOptIn"
	bcdedit /set `{current`} nx OptIn | Out-Null
}
# Disable SmartScreen Filter
Function DisableSmartScreen
{
	Write-Output "DisableSmartScreen"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 0 | Out-Null
}
# Enable SmartScreen Filter
Function EnableSmartScreen
{
	Write-Output "EnableSmartScreen"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Web Search in Start Menu
Function DisableWebSearch
{
	Write-Output "DisableWebSearch"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
}
# Enable Web Search in Start Menu
Function EnableWebSearch
{
	Write-Output "EnableWebSearch"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -ErrorAction SilentlyContinue
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -ErrorAction SilentlyContinue
}
# Disable Wi-Fi Sense
Function DisableWiFiSense
{
	Write-Output "DisableWiFiSense"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -Type DWord -Value 0
}
# Enable Wi-Fi Sense
Function EnableWiFiSense
{
	Write-Output "EnableWiFiSense"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 1 | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Activity History feed in Task View
Function DisableActivityHistory
{
	Write-Output "DisableActivityHistory"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 | Out-Null
}
# Enable Activity History feed in Task View
Function EnableActivityHistory
{
	Write-Output "EnableActivityHistory"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -ErrorAction SilentlyContinue | Out-Null
}
# Disable sensor features, such as screen auto rotation
Function DisableSensors
{
	Write-Output "DisableSensors"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1 | Out-Null
}
# Enable sensor features
Function EnableSensors
{
	Write-Output "EnableSensors"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -ErrorAction SilentlyContinue | Out-Null
}
# Disable location feature and scripting for the location feature
Function DisableLocation
{
	Write-Output "DisableLocation"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1 | Out-Null
}
# Enable location feature and scripting for the location feature
Function EnableLocation
{
	Write-Output "EnableLocation"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -ErrorAction SilentlyContinue | Out-Null
}
# Disable automatic Maps updates
Function DisableMapUpdates
{
	Write-Output "DisableMapUpdates"
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0 | Out-Null
}
# Enable automatic Maps updates
Function EnableMapUpdates
{
	Write-Output "EnableMapUpdates"
	Remove-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Feedback
Function DisableFeedback
{
	Write-Output "DisableFeedback"
	If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1 | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}
# Enable Feedback
Function EnableFeedback
{
	Write-Output "EnableFeedback"
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Tailored Experiences
Function DisableTailoredExperiences
{
	Write-Output "DisableTailoredExperiences"
	If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1 | Out-Null
}
# Enable Tailored Experiences
Function EnableTailoredExperiences
{
	Write-Output "EnableTailoredExperiences"
	Remove-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Advertising ID
Function DisableAdvertisingID
{
	Write-Output "DisableAdvertisingID"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1 | Out-Null
}
# Enable Advertising ID
Function EnableAdvertisingID
{
	Write-Output "EnableAdvertisingID"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue | Out-Null
}
# Disable setting 'Let websites provide locally relevant content by accessing my language list'
Function DisableWebLangList
{
	Write-Output "DisableWebLangList"
	Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value 1 | Out-Null
}
# Enable setting 'Let websites provide locally relevant content by accessing my language list'
Function EnableWebLangList
{
	Write-Output "EnableWebLangList"
	Remove-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -ErrorAction SilentlyContinue | Out-Null
}
# Disable biometric features
Function DisableBiometrics
{
	Write-Output "DisableBiometrics"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -Type DWord -Value 0 | Out-Null
}
# Enable biometric features
Function EnableBiometrics
{
	Write-Output "EnableBiometrics"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name "Enabled" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Error reporting
Function DisableErrorReporting
{
	Write-Output "DisableErrorReporting"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1 | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}
# Enable Error reporting
Function EnableErrorReporting
{
	Write-Output "EnableErrorReporting"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}
# Stop and disable Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
Function DisableDiagTrack
{
	Write-Output "DisableDiagTrack"
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
}
# Enable and start Connected User Experiences and Telemetry (previously named Diagnostics Tracking Service)
Function EnableDiagTrack
{
	Write-Output "EnableDiagTrack"
	Set-Service "DiagTrack" -StartupType Automatic
	Start-Service "DiagTrack" -WarningAction SilentlyContinue
}
# Stop and disable Device Management Wireless Application Protocol (WAP) Push Service
Function DisableWAPPush
{
	Write-Output "DisableWAPPush"
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
}
# Enable and start Device Management Wireless Application Protocol (WAP) Push Service
Function EnableWAPPush
{
	Write-Output "EnableWAPPush"
	Set-Service "dmwappushservice" -StartupType Automatic
	Start-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "DelayedAutoStart" -Type DWord -Value 1 | Out-Null
}
# Enable clearing of recent files on exit
Function EnableClearRecentFiles
{
	Write-Output "EnableClearRecentFiles"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -Type DWord -Value 1 | Out-Null
}
# Disable clearing of recent files on exit
Function DisableClearRecentFiles
{
	Write-Output "DisableClearRecentFiles"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ClearRecentDocsOnExit" -ErrorAction SilentlyContinue | Out-Null
}
# Disable recent files lists
Function DisableRecentFiles
{
	Write-Output "DisableRecentFiles"
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -Type DWord -Value 1 | Out-Null
}
# Enable recent files lists
Function EnableRecentFiles
{
	Write-Output "EnableRecentFiles"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -ErrorAction SilentlyContinue | Out-Null
}
Function MinimumDiagnosticLevel
{
	Write-Output "MinimumDiagnosticLevel"
	if (Get-WindowsEdition -Online | Where-Object -FilterScript {$_.Edition -like "Enterprise*" -or $_.Edition -eq "Education"})
			{
				New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 0 -Force | Out-Null
			}
			else
			{
				New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 1 -Force | Out-Null
			}

}
Function DefaultDiagnosticLevel
{
	Write-Output "DefaultDiagnosticLevel"
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection -Name AllowTelemetry -PropertyType DWord -Value 3 -Force | Out-Null
}
# Disable Application suggestions and automatic installation
Function DisableAppSuggestions
{
	Write-Output "DisableAppSuggestions"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Type DWord -Value 0 | Out-Null
	# Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
	If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
		$key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
		Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $key.Data[0..15]
		Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
	}
}
# Enable Application suggestions and automatic installation
Function EnableAppSuggestions
{
	Write-Output "EnableAppSuggestions"
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 1 | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Telemetry
Function DisableTelemetry
{
	Write-Output "DisableTelemetry"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0 | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue | Out-Null
}
# Enable Telemetry
Function EnableTelemetry
{
	Write-Output "EnableTelemetry"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 3 | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Office\Office ClickToRun Service Monitor" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentFallBack2016" -ErrorAction SilentlyContinue | Out-Null
	Enable-ScheduledTask -TaskName "Microsoft\Office\OfficeTelemetryAgentLogOn2016" -ErrorAction SilentlyContinue | Out-Null
}
# Explorer ribbon always start expanded
Function ShowExplorerRibbon
{
	Write-Output "ShowExplorerRibbon"
	if (!(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon"))
	{
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Force | Out-Null
	}
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "MinimizedStateTabletModeOff" -PropertyType DWord -Value 0 -Force | Out-Null
}
# Explorer ribbon always start minimized
Function HideExplorerRibbon
{
	Write-Output "HideExplorerRibbon"
	if (!(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon"))
	{
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Force | Out-Null
	}
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" -Name "MinimizedStateTabletModeOff" -PropertyType DWord -Value 1 -Force | Out-Null
}
# When I snap a window, do not show what I can snap next to it
Function DisableSnapAssist
{
	Write-Output "DisableSnapAssist"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SnapAssist" -PropertyType DWord -Value 0 -Force | Out-Null

}
# Hide frequently used folders in "Quick access"
Function HideQuickAccessFrequentFolders
{
	Write-Output "HideQuickAccessFrequentFolders"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -PropertyType DWord -Value 0 -Force | Out-Null
}
# Show frequently used folders in "Quick access"
Function ShowQuickAccessFrequentFolders
{
	Write-Output "ShowQuickAccessFrequentFolders"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -PropertyType DWord -Value 1 -Force | Out-Null
}

# Hide frequently used files in "Quick access"
Function HideQuickAccessFrequentFiles
{
	Write-Output "HideQuickAccessFrequentFiles"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -PropertyType DWord -Value 0 -Force | Out-Null
}
# Show frequently used files in "Quick access"
Function ShowQuickAccessFrequentFiles
{
	Write-Output "ShowQuickAccessFrequentFiles"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -PropertyType DWord -Value 1 -Force | Out-Null
}
# Hide the "Windows Ink Workspace" button on the taskbar
Function HideInkWorkSpace
{
	Write-Output "HideInkWorkSpace"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value 0 -Force | Out-Null
}
# Show the "Windows Ink Workspace" button on the taskbar
Function ShowInkWorkSpace
{
	Write-Output "ShowInkWorkSpace"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" -Name "PenWorkspaceButtonDesiredVisibility" -PropertyType DWord -Value 1 -Force | Out-Null
}
# Disable first sign-in animation after the upgrade
Function DisableFirstLogonAnimation
{
	Write-Output "DisableFirstLogonAnimation"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value 0 -Force | Out-Null
}
# Enable first sign-in animation after the upgrade
Function EnableFirstLogonAnimation
{
	Write-Output "EnableFirstLogonAnimation"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableFirstLogonAnimation" -PropertyType DWord -Value 1 -Force | Out-Null
}
# Set the quality factor of the JPEG desktop wallpapers to maximum
Function MaxJPEGWallpapersQuality
{
	Write-Output "MaxJPEGWallpapersQuality"
	New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -PropertyType DWord -Value 100 -Force | Out-Null
}
# Set the quality factor of the JPEG desktop wallpapers to default
Function DefaultJPEGWallpapersQuality
{
	Write-Output "DefaultJPEGWallpapersQuality"
	Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name JPEGImportQuality -Force -ErrorAction SilentlyContinue | Out-Null
}
# Disable notification when your PC requires a restart to finish updating
Function DisableUpdateRestartNotification
{
	Write-Output "DisableUpdateRestartNotification"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "RestartNotificationsAllowed2" -PropertyType DWord -Value 0 -Force | Out-Null

}
# Enable notification when your PC requires a restart to finish updating
Function EnableUpdateRestartNotification
{
	Write-Output "EnableUpdateRestartNotification"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "RestartNotificationsAllowed2" -PropertyType DWord -Value 1 -Force | Out-Null
}
# Do not let Windows decide which printer should be the default one
Function DisableWindowsManageDefaultPrinter
{
	Write-Output "DisableWindowsManageDefaultPrinter"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LegacyDefaultPrinterMode" -PropertyType DWord -Value 1 -Force | Out-Null
}
# Let Windows decide which printer should be the default one
Function EnableWindowsManageDefaultPrinter
{
	Write-Output "EnableWindowsManageDefaultPrinter"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LegacyDefaultPrinterMode" -PropertyType DWord -Value 0 -Force | Out-Null
}
# Restrict Windows Update P2P delivery optimization to computers in local network
Function SetP2PUpdateLocal
{
	Write-Output "SetP2PUpdateLocal"
		Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -ErrorAction SilentlyContinue | Out-Null
}
# Unrestrict Windows Update P2P delivery optimization to both local networks and internet
Function SetP2PUpdateInternet
{
	Write-Output "SetP2PUpdateInternet"
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 3 | Out-Null
}
# Disable Windows Update P2P delivery optimization completely (Will use BITS service)
Function SetP2PUpdateDisable
{
	Write-Output "SetP2PUpdateDisable"

		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -Type DWord -Value 100 | Out-Null
}
# Disable Fullscreen optimizations
Function DisableFullscreenOptims
{
	Write-Output "DisableFullscreenOptims"
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 2 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1 | Out-Null
}
# Enable Fullscreen optimizations
Function EnableFullscreenOptims
{
	Write-Output "EnableFullscreenOptims"
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -Type DWord -Value 0 | Out-Null
	Remove-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -ErrorAction SilentlyContinue | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -Type DWord -Value 0 | Out-Null
	Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 0 | Out-Null
}



# Disable built-in Adobe Flash in IE and Edge
Function DisableAdobeFlash
{
	Write-Output "Disabling built-in Adobe Flash in IE and Edge..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -Type DWord -Value 0 | Out-Null
}
# Enable built-in Adobe Flash in IE and Edge
Function EnableAdobeFlash
{
	Write-Output "EnableAdobeFlash"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" -Name "DisableFlashInIE" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Addons" -Name "FlashPlayerEnabled" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Edge preload after Windows startup - Applicable since Win10 1809
Function DisableEdgePreload
{
	Write-Output "DisableEdgePreload"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -Type DWord -Value 0 | Out-Null
}
# Enable Edge preload after Windows startup
Function EnableEdgePreload
{
	Write-Output "EnableEdgePreload"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Edge desktop shortcut creation after certain Windows updates are applied
Function DisableEdgeShortcutCreation
{
	Write-Output "DisableEdgeShortcutCreation"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -Type DWord -Value 1 | Out-Null
}
# Enable Edge desktop shortcut creation after certain Windows updates are applied
Function EnableEdgeShortcutCreation
{
	Write-Output "EnableEdgeShortcutCreation"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Internet Explorer first run wizard
Function DisableIEFirstRun
{
	Write-Output "DisableIEFirstRun"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Type DWord -Value 1 | Out-Null
}
# Enable Internet Explorer first run wizard
Function EnableIEFirstRun
{
	Write-Output "EnableIEFirstRun"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Windows Media Player's media sharing feature
Function DisableMediaSharing
{
	Write-Output "DisableMediaSharing"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -Type DWord -Value 1 | Out-Null
}
# Enable Windows Media Player's media sharing feature
Function EnableMediaSharing
{
	Write-Output "EnableMediaSharing"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -ErrorAction SilentlyContinue | Out-Null
}
# Disable Windows Media Player online access - audio file metadata download, radio presets, DRM.
Function DisableMediaOnlineAccess
{
	Write-Output "DisableMediaOnlineAccess"
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -Type DWord -Value 1 | Out-Null
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1 | Out-Null
}
# Enable Windows Media Player online access
Function EnableMediaOnlineAccess
{
	Write-Output "EnableMediaOnlineAccess"
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCDDVDMetadataRetrieval" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventMusicFileMetadataRetrieval" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventRadioPresetsRetrieval" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WMDRM" -Name "DisableOnline" -ErrorAction SilentlyContinue | Out-Null
}
# Enable Developer Mode
Function EnableDeveloperMode
{
	Write-Output "EnableDeveloperMode"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -Type DWord -Value 1 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Type DWord -Value 1 | Out-Null
}
# Disable Developer Mode
Function DisableDeveloperMode
{
	Write-Output "DisableDeveloperMode"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -ErrorAction SilentlyContinue | Out-Null
}
# Do not allow the computer to turn off the network adapters to save power
Function DisableNetSavePower
{
	Write-Output "DisableNetSavePower"
	$Adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement | Where-Object -FilterScript {$_.AllowComputerToTurnOffDevice -ne "Unsupported"}
	foreach ($Adapter in $Adapters)
	{
		$Adapter.AllowComputerToTurnOffDevice = "Disabled"
		$Adapter | Set-NetAdapterPowerManagement
	}
}
# Allow the computer to turn off the network adapters to save power
Function EnableNetSavePower
{
	Write-Output "EnableNetSavePower"
	$Adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement | Where-Object -FilterScript {$_.AllowComputerToTurnOffDevice -ne "Unsupported"}
	foreach ($Adapter in $Adapters)
	{
		$Adapter.AllowComputerToTurnOffDevice = "Enabled"
		$Adapter | Set-NetAdapterPowerManagement
	}
}
# Disable and delete reserved storage after the next update installation
Function DisableReservedStorage
{
	Write-Output "DisableReservedStorage"
	Set-WindowsReservedStorageState -State Disabled | Out-Null
}
# Enable reserved storage after the next update installation
Function EnableReservedStorage
{
	Write-Output "EnableReservedStorage"
	Set-WindowsReservedStorageState -State Enabled | Out-Null
}
# Disable automatically saving my restartable apps when signing out and restart them after signing in
Function DisableAppsAutoRestart
{
	Write-Output "DisableAppsAutoRestart"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "RestartApps" -Value 0 -Force | Out-Null

}
# Enable automatically saving my restartable apps when signing out and restart them after signing in
Function EnableAppsAutoRestart
{
	Write-Output "EnableAppsAutoRestart"
	New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "RestartApps" -Value 1 -Force | Out-Null
}
# Disable automatically adjusting active hours for me based on daily usage
Function DisableSmartActiveHours
{
	Write-Output "DisableSmartActiveHours"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "SmartActiveHoursState" -PropertyType DWord -Value 2 -Force | Out-Null
}
# Enable automatically adjusting active hours for me based on daily usage
Function EnableSmartActiveHours
{
	Write-Output "EnableSmartActiveHours"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "SmartActiveHoursState" -PropertyType DWord -Value 1 -Force | Out-Null
}
# Disable Microsoft Store automatic updates
Function DisableStoreUpdates
{
	Write-Output "DisableStoreUpdates"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value 2 | Out-Null
}
# Enable Microsoft Store automatic updates
Function EnableStoreUpdates
{
	Write-Output "EnableStoreUpdates"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -ErrorAction SilentlyContinue | Out-Null
}
# Disable restarting this device as soon as possible when a restart is required to install an update
Function DisableDeviceRestartAfterUpdate
{
	Write-Output "DisableDeviceRestartAfterUpdate"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "IsExpedited" -PropertyType DWord -Value 0 -Force | Out-Null
}
# Enable restarting this device as soon as possible when a restart is required to install an update
Function EnableDeviceRestartAfterUpdate
{
	Write-Output "EnableDeviceRestartAfterUpdate"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "IsExpedited" -PropertyType DWord -Value 1 -Force | Out-Null
}
# Disable Microsoft Defender Exploit Guard network protection
Function DisableExploitGuardNetworkProtection
{
	Write-Output "DisableExploitGuardNetworkProtection"
	Set-MpPreference -EnableNetworkProtection Disabled
}
# Enable Microsoft Defender Exploit Guard network protection
Function EnableExploitGuardNetworkProtection
{
	Write-Output "EnableExploitGuardNetworkProtection"
	Set-MpPreference -EnableNetworkProtection Enabled
}
# Disable detection for potentially unwanted applications and block them
Function DisablePUAppsDetection
{
	Write-Output "DisablePUAppsDetection"
	Set-MpPreference -PUAProtection Disabled
}
# Enable detection for potentially unwanted applications and block them
Function EnablePUAppsDetection
{
	Write-Output "EnablePUAppsDetection"
	Set-MpPreference -PUAProtection Enabled
}

# Disable sandboxing for Microsoft Defender
Function DisableDefenderSandbox
{
	Write-Output "DisableDefenderSandbox"
	setx /M MP_FORCE_USE_SANDBOX 0 | Out-Null
}
# Enable sandboxing for Microsoft Defender
Function EnableDefenderSandbox
{
	Write-Output "EnableDefenderSandbox"
	setx /M MP_FORCE_USE_SANDBOX 1 | Out-Null
}
# Hide the "Cast to Device" item from the context menu
Function HideCastToDeviceContext
{
	Write-Output "HideCastToDeviceContext"
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
	{
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -PropertyType String -Value "Play to menu" -Force | Out-Null
}
# Show the "Cast to Device" item from the context menu
Function ShowCastToDeviceContext
{
	Write-Output "ShowCastToDeviceContext"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" -Force -ErrorAction SilentlyContinue | Out-Null
}
# Hide the "Share" item from the context menu
Function HideShareContext
{
	Write-Output "HideShareContext"
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
	{
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -PropertyType String -Value "" -Force | Out-Null
}
# Show the "Share" item from the context menu
Function ShowShareContext
{
	Write-Output "ShowShareContext"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" -Force -ErrorAction SilentlyContinue | Out-Null
}
# Hide the "Edit with Paint 3D" item from the context menu
Function HideEditWithPaint3DContext
{
	Write-Output "HideEditWithPaint3DContext"
	$Extensions = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
	foreach ($extension in $extensions)
	{
		if ((Test-Path -Path "HKCR:\SystemFileAssociations\$Extension\Shell\3D Edit"))
		{
		New-ItemProperty -Path "HKCR:\SystemFileAssociations\$Extension\Shell\3D Edit" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
		}
	}
}
# Show the "Edit with Paint 3D" item from the context menu
Function ShowEditWithPaint3DContext
{
	Write-Output "ShowEditWithPaint3DContext"
	$Extensions = @(".bmp", ".gif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
	foreach ($Extension in $Extensions)	
	{
		if ((Test-Path -Path "HKCR:\SystemFileAssociations\$Extension\Shell\3D Edit"))
		{
		Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\$Extension\Shell\3D Edit" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
		}
	}
}
# Hide the "Edit with Photos" item from the context menu
Function HideEditWithPhotosContext
{
	Write-Output "HideEditWithPhotosContext"
	if ((Test-Path -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit"))
	{
	New-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	}
}
# Show the "Edit with Photos" item from the context menu
Function ShowEditWithPhotosContext
{
	Write-Output "ShowEditWithPhotosContext"
	if ((Test-Path -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit"))
	{
	Remove-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellEdit" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
}
}
# Hide the "Create a new video" item from the context menu
Function HideCreateANewVideoContext
{
	Write-Output "HideCreateANewVideoContext"
	if ((Test-Path -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo"))
	{
	New-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	}
}
# Show the "Create a new video" item from the context menu
Function ShowCreateANewVideoContext
{
	Write-Output "ShowCreateANewVideoContext"
	if ((Test-Path -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo"))
	{
	Remove-ItemProperty -Path "HKCR:\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc\Shell\ShellCreateVideo" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
}
}
# Hide the "Edit" item from the images context menu
Function HideImagesEditContext
{
	Write-Output "HideImagesEditContext"
	New-ItemProperty -Path "HKCR:\SystemFileAssociations\image\shell\edit" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
}
# Show the "Edit" item from the images context menu
Function ShowImagesEditContext
{
	Write-Output "ShowImagesEditContext"
	Remove-ItemProperty -Path "HKCR:\SystemFileAssociations\image\shell\edit" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
}
# Hide the "Print" item from the .bat and .cmd context menu
Function HidePrintCMDContext
{
	Write-Output "HidePrintCMDContext"
	if ((Test-Path -Path "HKCR:\batfile\shell\print"))
	{
		New-ItemProperty -Path "HKCR:\batfile\shell\print" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	}
	if ((Test-Path -Path "HKCR:\cmdfile\shell\print"))
	{
		New-ItemProperty -Path "HKCR:\cmdfile\shell\print" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	}


}
# Show the "Print" item from the .bat and .cmd context menu
Function ShowPrintCMDContext
{
	Write-Output "ShowPrintCMDContext"
	Remove-ItemProperty -Path "HKCR:\batfile\shell\print" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCR:\cmdfile\shell\print" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
}
# Hide the "Send to" item from the folders context menu
Function HideSendToContext
{
	Write-Output "HideSendToContext"
	New-ItemProperty -Path "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" -Name "(Default)" -PropertyType String -Value "-{7BA4C740-9E81-11CF-99D3-00AA004AE837}" -Force | Out-Null
}
# Show the "Send to" item from the folders context menu
Function ShowSendToContext
{
	Write-Output "ShowSendToContext"
	New-ItemProperty -Path "HKCR:\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo" -Name "(Default)" -PropertyType String -Value "{7BA4C740-9E81-11CF-99D3-00AA004AE837}" -Force | Out-Null
}
# Hide the "Turn on BitLocker" item from the context menu
Function HideBitLockerContext
{
	Write-Output "HideBitLockerContext"
	New-ItemProperty -Path "HKCR:\Drive\shell\encrypt-bde" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	New-ItemProperty -Path "HKCR:\Drive\shell\encrypt-bde-elev" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	New-ItemProperty -Path "HKCR:\Drive\shell\manage-bde" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	New-ItemProperty -Path "HKCR:\Drive\shell\resume-bde" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	New-ItemProperty -Path "HKCR:\Drive\shell\resume-bde-elev" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
	New-ItemProperty -Path "HKCR:\Drive\shell\unlock-bde" -Name "ProgrammaticAccessOnly" -PropertyType String -Value "" -Force | Out-Null
}
# Show the "Turn on BitLocker" item from the context menu
Function ShowBitLockerContext
{
	Write-Output "ShowBitLockerContext"
	Remove-ItemProperty -Path "HKCR:\Drive\shell\encrypt-bde" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCR:\Drive\shell\encrypt-bde-elev" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCR:\Drive\shell\manage-bde" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCR:\Drive\shell\resume-bde" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCR:\Drive\shell\resume-bde-elev" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKCR:\Drive\shell\unlock-bde" -Name "ProgrammaticAccessOnly" -Force -ErrorAction SilentlyContinue | Out-Null
}
# Hide the "Bitmap image" item from the "New" context menu
Function HideBitmapNewContext
{
	Write-Output "HideBitmapNewContext"
	Remove-Item -Path "HKCR:\.bmp\ShellNew" -Force -ErrorAction SilentlyContinue | Out-Null
}
# Remove Troubleshoot Compatibillity context
Function RemoveCompatibillityContext
{
	Write-Output "RemoveTroubleshootCompatibillityContext"
	if (-not (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked"))
	{
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Force | Out-Null
	}
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{1d27f844-3a1f-4410-85ac-14651078412d}" -PropertyType String -Value "" -Force | Out-Null
}
# Add Troubleshoot Compatibillity context
Function AddCompatibillityContext
{
	Write-Output "AddTroubleshootCompatibillityContext"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" -Name "{1d27f844-3a1f-4410-85ac-14651078412d}" -Force -ErrorAction SilentlyContinue | Out-Null
}
# Show the "Bitmap image" item from the "New" context menu
Function ShowBitmapNewContext
{
	Write-Output "ShowBitmapNewContext"
	if (-not (Test-Path -Path "HKCR:\.bmp\ShellNew"))
	{
		New-Item -Path "HKCR:\.bmp\ShellNew" -Force | Out-Null
	}
	New-ItemProperty -Path "HKCR:\.bmp\ShellNew" -Name "ItemName" -PropertyType ExpandString -Value "@%systemroot%\system32\mspaint.exe,-59414" -Force | Out-Null
	New-ItemProperty -Path "HKCR:\.bmp\ShellNew" -Name "NullFile" -PropertyType String -Value "" -Force | Out-Null
}
# Hide the "Rich Text Document" item from the "New" context menu
Function HideRichTextDocumentNewContext
{
	Write-Output "HideRichTextDocumentNewContext"
	Remove-Item -Path "HKCR:\.rtf\ShellNew" -Force -ErrorAction Ignore | Out-Null
}
# Show the "Rich Text Document" item from the "New" context menu
Function ShowRichTextDocumentNewContext
{
	Write-Output "ShowRichTextDocumentNewContext"
	if (-not (Test-Path -Path "HKCR:\.rtf\ShellNew"))
	{
		New-Item -Path "HKCR:\.rtf\ShellNew" -Force | Out-Null
	}
	New-ItemProperty -Path "HKCR:\.rtf\ShellNew" -Name "Data" -PropertyType String -Value "{\rtf1}" -Force | Out-Null
	New-ItemProperty -Path "HKCR:\.rtf\ShellNew" -Name "ItemName" -PropertyType ExpandString -Value "@%ProgramFiles%\Windows NT\Accessories\WORDPAD.EXE,-213" -Force | Out-Null
}
# Hide the "Compressed (zipped) Folder" item from the "New" context menu
Function HideCompressedFolderNewContext
{
	Write-Output "HideCompressedFolderNewContext"
	Remove-Item -Path "HKCR:\.zip\CompressedFolder\ShellNew" -Force -ErrorAction Ignore | Out-Null
}
# Show the "Compressed (zipped) Folder" item from the "New" context menu
Function ShowCompressedFolderNewContext
{
	Write-Output "ShowCompressedFolderNewContext"
	if (-not (Test-Path -Path "HKCR:\.zip\CompressedFolder\ShellNew"))
	{
		New-Item -Path "HKCR:\.zip\CompressedFolder\ShellNew" -Force | Out-Null
	}
	New-ItemProperty -Path "HKCR:\.zip\CompressedFolder\ShellNew" -Name "Data" -PropertyType Binary -Value ([byte[]](80,75,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)) -Force | Out-Null
	New-ItemProperty -Path "HKCR:\.zip\CompressedFolder\ShellNew" -Name "ItemName" -PropertyType ExpandString -Value "@%SystemRoot%\system32\zipfldr.dll,-10194" -Force | Out-Null
}
# Hide the "Previous Versions" tab from files and folders context menu and also the "Restore previous versions" context menu item
Function HidePreviousVersionsPage
{
	Write-Output "HidePreviousVersionsPage"
	New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "NoPreviousVersionsPage" -PropertyType DWord -Value 1 -Force | Out-Null
}
# Show the "Previous Versions" tab from files and folders context menu and also the "Restore previous versions" context menu item
Function ShowPreviousVersionsPage
{
	Write-Output "ShowPreviousVersionsPage"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "NoPreviousVersionsPage" -Force -ErrorAction SilentlyContinue | Out-Null
}
Function DisableUWPBackgroundApps
{
	Write-Output "DisableUWPBackgroundApps"
		If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
			New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
		}
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
}
# Enable UWP apps background access
Function EnableUWPBackgroundApps
{
	Write-Output "EnableUWPBackgroundApps"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to voice activation from UWP apps
Function DisableUWPVoiceActivation
{
	Write-Output "DisableUWPVoiceActivation"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -Type DWord -Value 2 | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -Type DWord -Value 2 | Out-Null
}
# Enable access to voice activation from UWP apps
Function EnableUWPVoiceActivation
{
	Write-Output "EnableUWPVoiceActivation"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoice" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsActivateWithVoiceAboveLock" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to notifications from UWP apps
Function DisableUWPNotifications
{
	Write-Output "DisableUWPNotifications"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -Type DWord -Value 2 | Out-Null
}
# Enable access to notifications from UWP apps
Function EnableUWPNotifications
{
	Write-Output "EnableUWPNotifications"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessNotifications" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to account info from UWP apps
Function DisableUWPAccountInfo
{
	Write-Output "DisableUWPAccountInfo"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -Type DWord -Value 2 | Out-Null
}
# Enable access to account info from UWP apps
Function EnableUWPAccountInfo
{
	Write-Output "EnableUWPAccountInfo"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessAccountInfo" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to contacts from UWP apps
Function DisableUWPContacts
{
	Write-Output "DisableUWPContacts"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -Type DWord -Value 2 | Out-Null
}
# Enable access to contacts from UWP apps
Function EnableUWPContacts
{
	Write-Output "EnableUWPContacts"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessContacts" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to calendar from UWP apps
Function DisableUWPCalendar
{
	Write-Output "DisableUWPCalendar"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -Type DWord -Value 2 | Out-Null
}
# Enable access to calendar from UWP apps
Function EnableUWPCalendar
{
	Write-Output "EnableUWPCalendar"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCalendar" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to phone calls from UWP apps
Function DisableUWPPhoneCalls
{
	Write-Output "DisableUWPPhoneCalls"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -Type DWord -Value 2 | Out-Null
}
# Enable access to phone calls from UWP apps
Function EnableUWPPhoneCalls
{
	Write-Output "EnableUWPPhoneCalls"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessPhone" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to call history from UWP apps
Function DisableUWPCallHistory
{
	Write-Output "DisableUWPCallHistory"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -Type DWord -Value 2 | Out-Null
}
# Enable access to call history from UWP apps
Function EnableUWPCallHistory
{
	Write-Output "EnableUWPCallHistory"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCallHistory" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to email from UWP apps
Function DisableUWPEmail
{
	Write-Output "DisableUWPEmail"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -Type DWord -Value 2 | Out-Null
}
# Enable access to email from UWP apps
Function EnableUWPEmail
{
	Write-Output "EnableUWPEmail"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessEmail" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to tasks from UWP apps
Function DisableUWPTasks
{
	Write-Output "DisableUWPTasks"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -Type DWord -Value 2 | Out-Null
}
# Enable access to tasks from UWP apps
Function EnableUWPTasks
{
	Write-Output "EnableUWPTasks"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessTasks" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to messaging (SMS, MMS) from UWP apps
Function DisableUWPMessaging
{
	Write-Output "DisableUWPMessaging"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -Type DWord -Value 2 | Out-Null
}
# Enable access to messaging from UWP apps
Function EnableUWPMessaging
{
	Write-Output "EnableUWPMessaging"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMessaging" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to radios (e.g. Bluetooth) from UWP apps
Function DisableUWPRadios
{
	Write-Output "DisableUWPRadios"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -Type DWord -Value 2 | Out-Null
}
# Enable access to radios from UWP apps
Function EnableUWPRadios
{
	Write-Output "EnableUWPRadios"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessRadios" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to other devices (unpaired, beacons, TVs etc.) from UWP apps
Function DisableUWPOtherDevices
{
	Write-Output "DisableUWPOtherDevices"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -Type DWord -Value 2 | Out-Null
}
# Enable access to other devices from UWP apps
Function EnableUWPOtherDevices
{
	Write-Output "EnableUWPOtherDevices"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsSyncWithDevices" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to diagnostic information from UWP apps
Function DisableUWPDiagInfo
{
	Write-Output "DisableUWPDiagInfo"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -Type DWord -Value 2 | Out-Null
}
# Enable access to diagnostic information from UWP apps
Function EnableUWPDiagInfo
{
	Write-Output "EnableUWPDiagInfo"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsGetDiagnosticInfo" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to libraries and file system from UWP apps
Function DisableUWPFileSystem
{
	Write-Output "DisableUWPFileSystem"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Deny" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Deny" | Out-Null
}
# Enable access to libraries and file system from UWP apps
Function EnableUWPFileSystem
{
	Write-Output "EnableUWPFileSystem"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Type String -Value "Allow" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Type String -Value "Allow" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Type String -Value "Allow" | Out-Null
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Type String -Value "Allow" | Out-Null
}
# Disable UWP apps swap file
Function DisableUWPSwapFile
{
	Write-Output "DisableUWPSwapFile"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -Type Dword -Value 0 | Out-Null
}
# Enable UWP apps swap file
Function EnableUWPSwapFile
{
	Write-Output "EnableUWPSwapFile"
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SwapfileControl" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to camera
Function DisableCamera
{
	Write-Output "DisableCamera"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -Type DWord -Value 2 | Out-Null
}
# Enable access to camera
Function EnableCamera
{
	Write-Output "EnableCamera"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessCamera" -ErrorAction SilentlyContinue | Out-Null
}
# Disable access to microphone
Function DisableMicrophone
{
	Write-Output "DisableMicrophone"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -Type DWord -Value 2 | Out-Null
}
# Enable access to microphone
Function EnableMicrophone
{
	Write-Output "EnableMicrophone"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsAccessMicrophone" -ErrorAction SilentlyContinue | Out-Null
}
# Set Desktop icons to small size
Function DesktopIconSizeSmall
{
	Write-Output "DesktopIconSizeSmall"
	Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -name IconSize -value 32 | Out-Null
	taskkill /f /im explorer.exe | Out-Null
	Start-Process explorer | Out-Null
}
# Set Desktop icons to medium size
Function DesktopIconSizeMedium
{
	Write-Output "DesktopIconSizeMedium"
	Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -name IconSize -value 48 | Out-Null
	taskkill /f /im explorer.exe | Out-Null
	Start-Process explorer | Out-Null
}
# Set Desktop icons to large size
Function DesktopIconSizeLarge
{
	Write-Output "DesktopIconSizeLarge"
	Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -name IconSize -value 96 | Out-Null
	taskkill /f /im explorer.exe | Out-Null
	Start-Process explorer | Out-Null
}
# Delete all Windows Firewall rules
Function FirewallDeleteAllRules
{
	Write-Output "FirewallDeleteAllRules"
	Remove-NetFirewallRule  | Out-Null
}
# Do not allow users to connect a microsoft account & allow apps to launch without microsoft account
Function BlockMicrosoftAccount
{
	Write-Output "BlockMicrosoftAccount"
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -Type DWord -Value 1 | Out-Null
	
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\System")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\System" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\System" -Name "MSAOptional" -Type DWord -Value 1 | Out-Null
}
# Allow users to connect a microsoft account & Do not allow apps to launch without microsoft account
Function AllowMicrosoftAccount
{
	Write-Output "AllowMicrosoftAccount"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" -Name "DisableUserAuth" -ErrorAction SilentlyContinue | Out-Null
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\System" -Name "MSAOptional" -ErrorAction SilentlyContinue | Out-Null
}
Function WaitForKey
{
	Write-Output "Press any key to continue"
	[Console]::ReadKey($true) | Out-Null
	#Restart-Computer
}
