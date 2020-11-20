# WindowsFresh  
## PowerShell Script for automated Windows 10 configuration.

Recommended to run on a fresh Windows installation, not really mandatory but it could cause some problems if current install is already tweaked by other methods.

And if you reinstall Windows, do it with a clean ISO provided by microsoft (Download Windows USB/DVD Download Tool by example) because it is not bloated by OEM manufacturers (HP,LENOVO etc...)

##### Does no support old Windows versions and LTSC versions, this script will works perfectly only on last Windows version (Actually Windows 10 20H2).




The script functionnalities are :

- ###  __Uninstall UWP Apps (WHITELIST)__ 

Remove all UWP bloat by default, the whitelist can be customized as well and most used UWP Apps like Camera, Photos, Calculator and Microsoft Store are not uninstalled by default, they are in the tweak preset file.

Removed Apps can be installed again without problems, it just remove it for this user, windows reinstall some after updates, just run the script again.

- ### __Disable Windows Services (BLACKLIST)__

Disable not frequently used services, blacklist can be customized as well.

- ### __Disable Windows Optional Features (BLACKLIST)__

Disable not frequently used Features, blacklist can be customized as well.

- ### __Disable Windows Optional Capabilities (BLACKLIST)__

Disable not frequently used Capabilities, blacklist can be customized as well.

- ### __Disable Scheduled Tasks (BLACKLIST)__

Disable privacy related tasks, auto updates tasks, diagnostics tasks, blacklist can be customized as well.

- ### __Remove Startup Entries (BLACKLIST)__

Remove blacklisted Startup Entries, blacklist can be customized as well.

- ### __Tweak the Windows (PRESET)__

Tweak the entire Windows from UI customization to Security in a single preset file, most of the tweaks have opposite option (show/hide,enable/disable) then in case you tweaked something you dont like, you can change it and run the script again.

Feels free to help on the project there just a single rule : Tweaks need to have opposite option Show/Hide by example.






You have choice to keep essentials Windows Apps :

![Image](https://github.com/innovatodev/WindowsFresh/blob/master/IMG/2.png)

Or remove everything you dont need :

![Image](https://github.com/innovatodev/WindowsFresh/blob/master/IMG/1.png)

By default, Windows Defender will protect you :

![Image](https://github.com/innovatodev/WindowsFresh/blob/master/IMG/3.png)





Most of the tweaks are taken from :

https://github.com/Disassembler0/Win10-Initial-Setup-Script

https://github.com/farag2/Windows-10-Sophia-Script

And added a lot myself too.










