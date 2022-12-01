<#
This script configures the target Windows 11 Client for compliance with CIS-benchmarks, Chapter 19, Level 1 registry keys


NOTE: Chapter 19 of CIS consists of modifications needed for all users on the system, this script can only apply these settings to users already present
on the target Windows 11 system. If new users are created, this script will need to be run again to apply these settings to the new user.
If users are regurlary added, deploying these settings via Domain Policy might be a better option for your use case.

Reference:
   CIS: https://learn.cisecurity.org/benchmarks
   Change registry keys: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg
   Registry settings: https://admx.help/

#>

<#
Find all the user profiles in the registry to apply the setting to.
#>

$users = Get-ChildItem Registry::HKEY_USERS


<#
Loop through each user known in the registry to apply the modifications in the registry.
#>

foreach($user in $users)
{

$HKEY_USER = $user.Name

#19.1.3.1 (L1) Ensure 'Enable screen saver' is set to 'Enabled' (Automated)
reg.exe add $HKEY_USER\"Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveActive /t REG_SZ /f /d 1

#19.1.3.2  (L1) Ensure 'Password protect the screen saver' is set to 'Enabled' (Automated)
reg.exe add $HKEY_USER\"Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaverIsSecure /t REG_SZ /f /d 1

#19.1.3.3 (L1) Ensure 'Screen saver timeout' is set to 'Enabled: 900 seconds or fewer, but not 0' (Automated)reg.exe add $HKEY_USER\"Software\Policies\Microsoft\Windows\Control Panel\Desktop" /v ScreenSaveTimeOut /t REG_DWORD /f /d 900

#19.5.1.1  (L1) Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled' (Automated)
reg.exe add $HKEY_USER\"Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoToastApplicationNotificationOnLockScreen /t REG_DWORD /f /d 1

#19.7.4.1 (L1) Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled' (Automated)
reg.exe add $HKEY_USER\"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v 	SaveZoneInformation /t REG_DWORD /f /d 2

#19.7.4.2  (L1) Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled' (Automated)
reg.exe add $HKEY_USER\"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v 	ScanWithAntiVirus /t REG_DWORD /f /d 3

#19.7.8.1  (L1) Ensure 'Configure Windows spotlight on lock screen' is set to Disabled' (Automated)
reg.exe add $HKEY_USER\"Software\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /t REG_DWORD /f /d 2

#19.7.8.2 (L1) Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled' (Automated)
reg.exe add $HKEY_USER\"Software\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /f /d 1  
   
#19.7.8.5 (L1) Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled' (Automated)
reg.exe add $HKEY_USER\"Software\Policies\Microsoft\Windows\CloudContent" /v DisableSpotlightCollectionOnDesktop /t REG_DWORD /f /d 1  

#19.7.28.1 (L1) Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled' (Automated)
reg.exe add $HKEY_USER\"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInplaceSharing /t REG_DWORD /f /d 1 

#19.7.43.1 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled' (Automated)
reg.exe add $HKEY_USER\"Software\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated /t REG_DWORD /f /d 0
  
   
}