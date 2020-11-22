# WindowsFresh
## PowerShell Script for automated Windows 10 configuration.

Recommended to run on a fresh Windows installation, not really mandatory but it could cause some problems if current install is already tweaked by other methods.

And if you reinstall Windows, do it with a clean ISO provided by microsoft (Download Windows USB/DVD Download Tool by example) because it is not bloated by OEM manufacturers (HP,LENOVO etc...)

##### Does no support old Windows versions and LTSC versions, this script will works perfectly only on last Windows version (Actually Windows 10 20H2).




The script functionnalities are :

- ###  __Uninstall UWP Apps (WHITELIST)__

Remove all UWP bloat by default, the whitelist can be customized as well and not useless UWP Apps like Camera, Photos, Calculator and Microsoft Store are not uninstalled by default, they are in the tweak preset file.

Removed Apps can be installed again without problems, if Windows add new useless UWP Apps in the future, the whitelist system will catch these too, just run the script again !

- ### __Disable Windows Services (BLACKLIST)__

Disable not frequently used services, blacklist can be customized as well.

- ### __Disable Windows Optional Features (BLACKLIST)__

Disable not frequently used Features, blacklist can be customized as well.

- ### __Disable Windows Optional Capabilities (BLACKLIST)__

Disable not frequently used Capabilities, blacklist can be customized as well.

- ### __Disable Scheduled Tasks (BLACKLIST)__

Disable privacy related tasks, auto updates tasks, diagnostics tasks, blacklist can be customized as well.

- ### __Remove Startup Entries (BLACKLIST)__

Remove Startup Entries, blacklist can be customized as well.

- ### __Tweak the Windows (PRESET)__

Tweak the entire Windows from UI customization to Security in a single preset file, most of the tweaks have opposite option (show/hide,enable/disable) then in case you tweaked something you dont like, you can change it and run the script again.

Feels free to help on the project there just a single rule : Tweaks need to have opposite option Show/Hide by example.






You have choice to keep essentials Windows Apps :

![Image](https://camo.githubusercontent.com/fe4bbc58611f6a1a84022fdd376cbad13214f0b5284e66dbffb4d143f6239b6d/68747470733a2f2f692e696d6775722e636f6d2f763055594744642e706e67)

Or remove everything you dont need :

![Image](https://camo.githubusercontent.com/c13973059e30c09a5e06b5db21531c134e63fccf8ed754421eb991c7efae1521/68747470733a2f2f692e696d6775722e636f6d2f48704b3875747a2e706e67)

By default, Windows Defender will protect you :

![Image](https://camo.githubusercontent.com/c13973059e30c09a5e06b5db21531c134e63fccf8ed754421eb991c7efae1521/68747470733a2f2f692e696d6775722e636f6d2f48704b3875747a2e706e67)





Thanks to :

https://github.com/Disassembler0/Win10-Initial-Setup-Script

https://github.com/farag2/Windows-10-Sophia-Script

Lot of tweaks are taken from here, i added/modified a lot but a big part are from these two repositories










