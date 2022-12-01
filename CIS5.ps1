<#
This script configures the target Windows 11 Client for compliance with CIS-benchmarks, Chapter 5, Level 1.
Some recommendations consists of a specific time period, for example 180 to 365 days. These entries can be modified by using the variables in this script.
The standaard values in this script are the first value mentioned in the range. 
For example between 180 and 365 days, 180 days is configured as the default value.
For Not fewer than 10 days, 10 days is configured as the default value.
For not longer than 15 days, 15 days is configured as the default value. 

Reference:
   CIS: https:  learn.cisecurity.org/benchmarks
   Change registry keys: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkForRegKey?view=powershell-7.2
   Registry settings: https://admx.help/
#>



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


#5.8 (L1) Ensure 'Internet Connection Sharing (ICS) (SharedAccess)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" "start"   4   dword

#5.24 (L1) Ensure 'Remote Procedure Call (RPC) Locator (RpcLocator)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" "start"   4   dword

#5.26 (L1) Ensure 'Routing and Remote Access (RemoteAccess)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" "start"   4   dword

#5.31 (L1) Ensure 'SSDP Discovery (SSDPSRV)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" "start"   4   dword

#5.32 (L1) Ensure 'UPnP Device Host (upnphost)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" "start"   4   dword

#5.36 (L1) Ensure 'Windows Media Player Network Sharing Service (WMPNetworkSvc)' is set to 'Disabled' or 'Not Installed' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" "start"   4   dword

#5.37 (L1) Ensure 'Windows Mobile Hotspot Service (icssvc)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc" "start"   4   dword

#5.42(L1) Ensure 'Xbox Accessory Management Service (XboxGipSvc)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"  "start"   4   dword

#5.43(L1) Ensure 'Xbox Live Auth Manager (XblAuthManager)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"  "start"   4   dword

#5.44(L1) Ensure 'Xbox Live Game Save (XblGameSave)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave" "start"   4   dword

#5.45 (L1) Ensure 'Xbox Live Networking Service (XboxNetApiSvc)' is set to 'Disabled' (Automated)
checkForRegKey "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" "start"   4   dword
