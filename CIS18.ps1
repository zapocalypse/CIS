<#
This script configures the target Windows 11 Client for compliance with CIS-benchmarks, Chapter 18, Level 1 registry keys
Some recommendations consists of a specific time period, for example 180 to 365 days. These entries can be modified by using the variables in this script.
The standaard values in this script are the first value mentioned in the range. 
For example between 180 and 365 days, 180 days is configured as the default value.
For Not fewer than 10 days, 10 days is configured as the default value.
For not longer than 15 days, 15 days is configured as the default value. 

Reference:
   CIS: https://learn.cisecurity.org/benchmarks
   Change registry keys: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkForRegKey?view=powershell-7.2
   Registry settings: https://admx.help/

#>

<#
Default values used in this script:

$passwordLength =  15 
$maxPasswordAge = 30 
$DODownloadMode = 1  
$maxSizeApplicationLogsInKB = 32768 
$maxSizeSecurityLogsInKB = 196608 
$maxSizeSetupLogsInKB = 32768 
$maxSizeSystemLogsInKB = 32768
$allowWindowsInkWorkspace = 1
$deferFeatureUpdatesPeriodInDays = 365
#>

<#
Password policy:

Minumum password length. 15 or more acccording to CIS benchmarks.
Maximum password age in days. 30 or less acccording to CIS benchmarks.
#>
$passwordLength = 15 
$maxPasswordAge = 30 

<#
Windows Updates

Download method that Delivery Optimization uses for Windows Updates. Must not be set to 3 acccording to CIS benchmarks

0 = HTTP only, no peering.
1 = HTTP blended with peering behind the same NAT.
2 = HTTP blended with peering across a private group. Peering occurs on devices in 
the same Active Directory Site (if exist) or the same domain by default. When this 
option is selected, peering will cross NATs. To create a custom group use Group ID 
in combination with Mode 2.
3 = HTTP blended with Internet Peering.
99 = Simple download mode with no peering. Delivery Optimization downloads 
using HTTP only and does not attempt to contact the Delivery Optimization cloud 
services.
100 = Bypass mode. Do not use Delivery Optimization and use BITS instead.


Select when feature updates are received. Must be 180 or more days acccording to CIS benchmarks.
#>
$DODownloadMode = 1  
$deferFeatureUpdatesPeriodInDays = 180


<#
Windows Logging

Minimallog sizes for various log types.
Must be 32768kb or higher according to CIS benchmarks for application, setup and system logs.
Must be 196608kb or more according to CIS benchmarks for security logs.
#>
$maxSizeApplicationLogsInKB = 32768 
$maxSizeSecurityLogsInKB = 196608 
$maxSizeSetupLogsInKB = 32768 
$maxSizeSystemLogsInKB = 32768

<#
Accessing apps while the system is logged

0 -Disabled
1- On, On, but disallow access above lock
2- On 

Cannot be on 2 - Enabled according to CIS benchmarks.

#>
$allowWindowsInkWorkspace = 1 #Accessing apps while the system is logged


<#
Function for applying the registry values denfined in the registry key section of the script.
Must take the registy path, the name of the registry key, the desired value and the registy value type.

This function also checks if the registry key already exists, if not the registy key will be created.
Otherwise the script would return an error while attempting to change a value that does not exist.

Applies settings to the registry key, or after the registry key is created.

#>

function checkForRegKey($path, $name, $value, $type) {

try {

if (!(Test-Path -Path "$path\$name")) {

    
    
    New-Item -Path $($path) -Name $($name) -Force -ErrorAction Stop
     
    }

    New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force -ErrorAction Stop

}catch {
Write-Output $Error[0]
}
}

<#
Registry modifications
#>


#18.1.1.1 (L1) Ensure 'Prevent enabling lock screen camera' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockSlideShow" 1 DWord -Force

#18.1.1.2 (L1) Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreenCamera" 1  DWord -Force	

#18.1.2.2 (L1) Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization"  0  DWord -Force

#18.2.2	(L1) Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PwdExpirationProtectionEnabled"  1  DWord -Force	

#18.2.3 (L1) Ensure 'Enable Local Admin Password Management' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PwdExpirationProtectionEnabled"  1  DWord -Force	

#18.2.4 (L1) Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PasswordComplexity"  4  DWord -Force	

#18.2.5 (L1) Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PasswordLength"  "$($passwordLength)"  DWord -Force	

#18.2.6 (L1) Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" "PasswordAgeDays"  "$($maxPasswordAge)" DWord -Force	

#18.3.1 (L1) Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LocalAccountTokenFilterPolicy"  0  DWord -Force	

#18.3.2 (L1) Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10" "Start"  4  DWord -Force	

#18.3.3 (L1) Ensure 'Configure SMB v1 server' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"  0  DWord -Force	

#18.3.4 (L1) Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "DisableExceptionChainValidation"  0  DWord -Force	

#18.3.5 (L1) Ensure 'Limits print driver installation to Administrators' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint" "RestrictDriverInstallationToAdministrators"  1  DWord -Force	

#18.3.6 (L1) Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" "NodeType"  2  DWord -Force	

#18.3.7 (L1) Ensure 'WDigest Authentication' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"  0  DWord -Force

#18.4.1	(L1) Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"  0  DWord -Force

#18.4.2	(L1) Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisableIPSourceRouting"  2  DWord -Force	

#18.4.3 (L1) Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "DisableIPSourceRouting"  2  DWord -Force

#18.4.5	(L1) Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect"  0  DWord -Force	

#18.4.7 (L1) Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" "NoNameReleaseOnDemand"  1  DWord -Force	

#18.4.9 (L1) Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager//state: present" "SafeDllSearchMode"  1  DWord -Force	

#18.4.10 (L1) Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon//state: present" "ScreenSaverGracePeriod"  5  String -Force

#18.4.13 (L1) Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less' (Automated)
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" "WarningLevel"  90  DWord -Force	

#18.5.4.1 (L1) Ensure 'Configure DNS over HTTPS (DoH) name resolution' is set to 'Enabled: Allow DoH' or higher (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "DoHPolicy"  2  DWord -Force	

#18.5.4.2 (L1) Ensure 'Turn off multicast name resolution' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"  0  DWord -Force	

#18.5.8.1 (L1) Ensure 'Enable insecure guest logons' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" "AllowInsecureGuestAuth"  0  DWord -Force	

#18.5.11.2 (L1) Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connection" "NC_AllowNetBridge_NLA"  0  DWord -Force	

#18.5.11.3 (L1) Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connection" "NC_ShowSharedAccessUI"  0  DWord -Force	

#18.5.11.4 (L1) Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connection" "NC_StdDomainUserSetLocation"  1  DWord -Force	

#18.5.14.1a (L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares' (Automated
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Networkprovider\HardenedPaths" "\\*\NETLOGON"  RequireMutualAuthentication=1, RequireIntegrity=1  String -Force 
 
#18.5.14.1.b	(L1) Ensure 'Hardened UNC Paths' is set to 'Enabled, with "Require Mutual Authentication" and "Require Integrity" set for all NETLOGON and SYSVOL shares' (Automated
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Networkprovider\HardenedPaths" "\\*\SYSVOL"  RequireMutualAuthentication=1, RequireIntegrity=1  String -Force 
 
#18.5.21.1 (L1) Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fMinimizeConnections"  3  DWord -Force	

#18.5.21.2 (L1) Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" "fBlockNonDomain"  1  DWord -Force	

#18.5.23.2 (L1) Ensure 'Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM"  1  DWord -Force	

#18.6.1 (L1) Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "RegisterSpoolerRemoteRpcEndPoint"  2  DWord -Force	

#18.6.2 (L1) Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "NoWarningNoElevationOnInstall"  0  DWord -Force	

#18.6.3 (L1) Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "UpdatePromptSettings"  0  DWord -Force	

#18.8.3.1 (L1) Ensure 'Include command line in process creation events' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\SYSTEM\Audit" "ProcessCreationIncludeCmdLine_Enabled"  1  DWord -Force

#18.8.4.1 (L1) Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" "AllowEncryptionOracle"  0  DWord -Force

#18.8.4.2 (L1) Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" "AllowProtectedCreds"  1  DWord -Force	

#18.8.7.2 (L1) Ensure 'Prevent device metadata retrieval from the Internet' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetworks"  1  DWord -Force

#18.8.14.1 (L1) Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical' (Automated
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" "DriverLoadPolicy"  3  DWord -Force	

#18.8.21.2 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoBackgroundPolicy"  0  DWord -Force	

#18.8.21.3 (L1) Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" "NoGPOListChanges"  0  DWord -Force	

#18.8.21 4 (L1) Ensure 'Continue experiences on this device' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp"  0  DWord -Force	

#18.8.21.5 (L1) Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableBkGndGroupPolicy"  0  DWord -Force	

#18.8.22.1.2 (L1) Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload"  0  DWord -Force	

#18.8.22.1.6 (L1) Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoWebServices"  1  DWord -Force
	
#18.8.28.1 (L1) Ensure 'Block user from showing account details on sign-in' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockUserFromShowingAccountDetailsOnSignin"  1  DWord -Force	

#18.8.28.2 (L1) Ensure 'Do not display network selection UI' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontDisplayNetworkSelectionUI"  1  DWord -Force	

#18.8.28.3 (L1) Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DontEnumerateConnectedUsers"  1  DWord -Force	

#18.8.28.4 (L1) Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnumerateLocalUsers"  0  DWord -Force	

#18.8.28.5 (L1) Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "DisableLockScreenAppNotifications"  1  DWord -Force

#18.8.28.6 (L1) Ensure 'Turn off picture password sign-in' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "BlockDomainPicturePassword"  1  DWord -Force	

#18.8.28.7 (L1) Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "AllowDomainPINLogon"  0  DWord -Force	

#18.8.34.6.1 (L1) Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" "DCSettingIndex"  0  DWord -Force	

#18.8.34.6.2 (L1) Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9" "ACSettingIndex"  0  DWord -Force	

#18.8.34.6.5 (L1) Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "DCSettingIndex"  1  DWord -Force	

#18.8.34.6.6 (L1) Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" "ACSettingIndex"  1  DWord -Force	

#18.8.36.1 (L1) Ensure 'Configure Offer Remote Assistance' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowUnsolicited"  0  DWord -Force	

#18.8.36.2 (L1) Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fAllowToGetHelp"  0  DWord -Force	

#18.8.37.1 (L1) Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "EnableAuthEpResolution"  1  DWord -Force	

#18.8.37.2 (L1) Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" "RestrictRemoteClients"  1  DWord -Force	

#18.9.4.2 (L1) Ensure 'Prevent non-admin users from installing packaged Windows apps' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" "BlockNonAdminUserInstall"  1  DWord -Force	

#18.9.5.1 (L1) Ensure 'Let Windows apps activate with voice while the system is locked' is set to 'Enabled: Force Deny' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivac" "LetAppsActivateWithVoiceAboveLock"  2  DWord -Force	

#18.9.6.1 (L1) Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MSAOptional"  1  DWord -Force	

#18.9.8.1 (L1) Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoAutoplayfornonVolume"  1  DWord -Force	

#18.8.8.2 (L1) Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoAutorun"  1  DWord -Force	

#18.9.8.3 (L1) Ensure 'Turn off Autoplay' is set to 'Enabled: All drives' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"  255  DWord -Force	

#18.9.10.1.1 (L1) Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing"  1  DWord -Force	

#18.9.14.1 (L1) Ensure 'Turn off cloud consumer account state content' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableConsumerAccountStateContent"  1  DWord -Force	

#18.9.14.3 (L1) Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures"  1  DWord -Force	

#18.9.15.1 (L1) Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" "RequirePinForPairing"  2  DWord -Force	

#18.9.16.1 (L1) Ensure 'Do not display the password reveal button' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI" "DisablePasswordReveal"  1  DWord -Force	

#18.9.16.2 (L1) Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI" "EnumerateAdministrators"  0  DWord -Force	

#18.9.17.1 (L1) Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"  1  DWord -Force	

#18.9.17.3 (L1) Ensure 'Disable OneSettings Downloads' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DisableOneSettingsDownloads"  1  DWord -Force	

#18.9.17.4 (L1) Ensure 'Do not show feedback notifications' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications"  1  DWord -Force	

#18.9.17.5 (L1) Ensure 'Enable OneSettings Auditing' is set to 'Enabled' (Automated) 
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "EnableOneSettingsAuditing"  1  DWord -Force	

#18.9.17.6 (L1) Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDiagnosticLogCollection"  1  DWord -Force	

#18.9.17.7 (L1) Ensure 'Limit Dump Collection' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "LimitDumpCollection"  1  DWord -Force	

#18.9.17.8 (L1) Ensure 'Toggle user control over Insider builds' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" "AllowBuildPreview"  0  DWord -Force	
 
#18.9.18.1 (L1) Ensure 'Download Mode' is NOT set to 'Enabled: Internet' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" "$($DODownloadMode)" DWord -Force	

#18.9.27.1.1 (L1) Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "Retention"  0  String -Force  	

#18.9.27.1.2 (L1) Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" "MaxSize"  "$($maxSizeApplicationLogsInKB)" DWord -Force	

#18.9.27.2.1 (L1) Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "Retention"  0  String -Force  	

#18.9.27.2.2 (L1) Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" "MaxSize"  "$($maxSizeSecurityLogsInKB)" DWord -Force	

#18.9.27.3.1 (L1) Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "Retention"  0  String -Force  	

#18.9.27.3.2 (L1) Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup" "MaxSize"  "$($maxSizeSetupLogsInKB)" DWord -Force	

#18.9.27.4.1 (L1) Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "Retention"  0  String -Force  	

#18.9.27.4.2 (L1) Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" "MaxSize"  "$($maxSizeSystemLogsInKB)" DWord -Force	

#18.9.31.2 (L1) Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention"  0  DWord -Force	

#18.9.31.3 (L1) Ensure 'Turn off heap termination on corruption' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption"  0  DWord -Force	

#18.9.31.3 (L1) Ensure 'Turn off shell protocol protected mode' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "PreXPSP2ShellProtocolBehavior"  0  DWord -Force	
 
#18.9.36.1 (L1) Ensure 'Prevent the computer from joining a homegroup' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" "DisableHomeGroup"  1  DWord -Force	

#18.9.46.1 (L1) Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount" "DisableUserAuth"  1  DWord -Force	

#18.9.47.4.1 (L1) Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" "LocalSettingOverrideSpynetReporting"  0  DWord -Force	

#18.9.47.5.1.1 (L1) Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" "ExploitGuard_ASR_Rules"  1  DWord -Force	

#18.9.47.5.1.2a (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "26190899-1602-49e8-8b27-eb1d0a1ce869"  1  DWord -Force	

#18.9.47.5.1.2b (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "3b576869-a4ec-4529-8536-b80a7769e899"  1  DWord -Force	

#18.9.47.5.1.2c (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "5beb7efe-fd9a-4556-801d-275e5ffc04cc"  1  DWord -Force	

#18.9.47.5.1.2d (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"  1  DWord -Force	

#18.9.47.5.1.2e (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"  1  DWord -Force	

#18.9.47.5.1.2f (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"  1  DWord -Force	

#18.9.47.5.1.2g (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"  1  DWord -Force	

#18.9.47.5.1.2h (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"  1  DWord -Force	

#18.9.47.5.1.2i (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"  1  DWord -Force	

#18.9.47.5.1.2j (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d3e037e1-3eb8-44c8-a917-57927947596d"  1  DWord -Force	

#18.9.47.5.1.2k (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "d4f940ab-401b-4efc-aadc-ad5f3c50688a"  1  DWord -Force	

#18.9.47.5.1.2l (L1) Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" "e6db77e5-3df2-4cf1-b95a-636979351e5b"  1  DWord -Force	

#18.9.47.5.3.1 (L1) Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\windows Defender\Windows Defender Exploit Guard\Network Protection" "EnableNetworkProtection"  1  DWord -Force	

#18.9.47.9.1 (L1) Ensure 'Scan all downloaded files and attachments' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableIOAVProtection"  0  DWord -Force	

#18.9.47.9.2 (L1) Ensure 'Turn off real-time protection' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring"  0  DWord -Force	

#18.9.47.9.3 (L1) Ensure 'Turn on behavior monitoring' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableBehaviorMonitoring"  0  DWord -Force	

#18.9.47.9.4 (L1) Ensure 'Turn on script scanning' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableScriptScanning"  0  DWord -Force	

#18.9.47.12.1 (L1) Ensure 'Scan removable drives' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableRemovableDriveScanning"  0  DWord -Force	

#18.9.47.12.2 (L1) Ensure 'Turn on e-mail scanning' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" "DisableEmailScanning"  0  DWord -Force	

#18.9.47.15 (L1) Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "PUAProtection"  1  DWord -Force	

#18.9.47.16 (L1) Ensure 'Turn off Microsoft Defender AntiVirus' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware"  0  DWord -Force	

#18.9.58.1 (L1) Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC"  1  DWord -Force	

#19.8.65.2.2 (L1) Ensure 'Do not allow passwords to be saved' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving"  1  DWord -Force	

#18.9.65.3.3.3 (L1) Ensure 'Do not allow drive redirection' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm"  1  DWord -Force	

#18.9.65.3.9.1 (L1) Ensure 'Always prompt for password upon connection' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword"  1  DWord -Force	

#18.9.65.3.9.2 (L1) Ensure 'Require secure RPC communication' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fEncryptRPCTraffic"  1  DWord -Force	

#18.9.65.3.9.3 (L1) Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "SecurityLayer"  2  DWord -Force	

#18.9.65.3.9.4 (L1) Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication"  1  DWord -Force	

#18.9.65.3.9.5 (L1) Ensure 'Set client connection encryption level' is set to 'Enabled: High Level' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"  2  DWord -Force	

#18.9.65.3.11.1 (L1) Ensure 'Do not delete temp folders upon exit' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit"  1  DWord -Force	

#18.9.66.1 (L1) Ensure 'Prevent downloading of enclosures' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds" "DisableEnclosureDownload"  1  DWord -Force	

#18.9.67.3 (L1) Ensure 'Allow Cortana' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana"  0  DWord -Force	

#18.9.67.4 (L1) Ensure 'Allow Cortana above lock screen' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortanaAboveLock"  0  DWord -Force	

#18.9.67.5 (L1) Ensure 'Allow indexing of encrypted files' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems"  0  DWord -Force	

#18.9.67.6 (L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation"  0  DWord -Force	

#18.9.75.2 (L1) Ensure 'Allow search and Cortana to use location' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "RequirePrivateStoreOnly"  1  DWord -Force	

#18.9.75.3  (L1) Ensure 'Turn off Automatic Download and Install of updates' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload"  4  DWord -Force	

#18.9.75.4 (L1) Ensure 'Turn off the offer to update to the latest version of Windows' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "DisableOSUpgrade"  1  DWord -Force	

#18.9.81.1 (L1) Ensure 'Allow widgets' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" "AllowNewsAndInterests"  0  DWord -Force	

#18.9.85.1.1a (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"  1  DWord -Force	
 
#18.9.85.1.1b (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "ShellSmartScreenLevel"  Block  String -Force  	

#18.9.85.2.1 (L1) Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "EnabledV9"  1  DWord -Force	

#18.9.85.2.2 (L1) Ensure 'Prevent bypassing Windows Defender SmartScreen prompts for sites' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "PreventOverride"  1  DWord -Force	

#18.9.87.1 (L1) Ensure 'Enables or disables Windows Game Recording and Broadcasting' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR"  0  DWord -Force	

#18.9.89.2 (L1) Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock' OR 'Disabled' but not 'Enabled: On' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" "AllowWindowsInkWorkspace"  "$($allowWindowsInkWorkspace)" DWord -Force	

#18.9.90.1 (L1) Ensure 'Allow user control over installs' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "EnableUserControl"  0  DWord -Force	

#18.9.90.2 (L1) Ensure 'Always install with elevated privileges' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "AlwaysInstallElevated"  0  DWord -Force	

#18.9.91.1 (L1) Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn"  1  DWord -Force	

#18.9.10.1 (L1) Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"  1  DWord -Force	

#18.9.100.2 (L1) Ensure 'Turn on PowerShell Transcription' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"  0  DWord -Force	

#18.9.102.1.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic"  0  DWord -Force	

#18.9.102.1.2 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowUnencryptedTraffic"  0  DWord -Force	

#18.9.102.1.3 (L1) Ensure 'Disallow Digest authentication' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowDigest"  0  DWord -Force	

#18.9.102.2.1 (L1) Ensure 'Allow Basic authentication' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowBasic"  0  DWord -Force	

#18.9.102.2.3 (L1) Ensure 'Allow unencrypted traffic' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "AllowUnencryptedTraffic"  0  DWord -Force	

#18.9.103.2.4 (L1) Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" "DisableRunAs"  1  DWord -Force	

#18.9.104.1 (L1) Ensure 'Allow clipboard sharing with Windows Sandbox' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" "AllowClipboardRedirection"  0  DWord -Force	

#18.9.104.2 (L1) Ensure 'Allow networking in Windows Sandbox' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox" "AllowNetworking"  0  DWord -Force	

#18.9.105.2.1 (L1) Ensure 'Prevent users from modifying settings' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" "DisallowExploitDisallowExploitProtectionOverride"  1  DWord -Force	

#18.9.108.1.1 (L1) Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers"  0  DWord -Force	

#18.9.108.2.1 (L1) Ensure 'Configure Automatic Updates' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"  0  DWord -Force	

#18.9.108.2.2 (L1) Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay"  0  DWord -Force	

#18.9.108.2.3 (L1) Ensure 'Remove access to “Pause updates” feature' is set to 'Enabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "SetDisablePauseUXAccess"  1  DWord -Force	

#18.9.108.4.1 (L1) Ensure 'Manage preview builds' is set to 'Disabled' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "ManagePreviewBuildsPolicyValue"  1  DWord -Force	

#18.9.108.4.2a (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdate"  1  DWord -Force	

#18.9.108.4.2b (L1) Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferFeatureUpdatesPeriodInDays"  "$($deferFeatureUpdatesPeriodInDays)" DWord -Force	

#18.9.108.4.3a (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdates"  1  DWord -Force	

#18.9.108.4.3b (L1) Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' (Automated)
checkForRegKey  "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" "DeferQualityUpdatesPeriodInDays"  0  DWord -Force	



