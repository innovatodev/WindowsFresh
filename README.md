# WindowsFresh  
PowerShell Script for automated Windows 10 configuration.

It is recommended to run on a fresh Windows installation, not really mandatory but it could cause some problems if current install is already tweaked by other methods.

Do no support old Windows versions and LTSC versions, this script will works perfectly only on last Windows version (Actually Windows 10 20H2)

1-Uninstall UWP Apps (WHITELIST)

Remove all UWP bloat by default, the whitelist can be customized as well and most used UWP Apps like Camera, Photos, Calculator and Microsoft Store are not uninstalled by default, they are in the tweak preset file.

Removed Apps can be installed again without problems, it just remove it for this user, windows reinstall some after updates, just run the script again.

2-Disable Windows Services (BLACKLIST)

Disable not frequently used services, blacklist can be customized as well.

3-Disable Windows Optional Features (BLACKLIST)

Disable not frequently used Features, blacklist can be customized as well.

4-Disable Windows Optional Capabilities (BLACKLIST)

Disable not frequently used Capabilities, blacklist can be customized as well.

5-Disable Scheduled Tasks (BLACKLIST)

Disable privacy related tasks, auto updates tasks, diagnostics tasks, blacklist can be customized as well.

6-Tweak the Windows (PRESET)

Tweak the entire Windows from UI customization to Security in a single preset file, most of the tweaks have opposite option (show/hide,enable/disable) then in case you tweaked something you dont like, you can change it and run the script again.








Most of the tweaks are taken from :

https://github.com/Disassembler0/Win10-Initial-Setup-Script

https://github.com/farag2/Windows-10-Sophia-Script

And added a lot myself too.










