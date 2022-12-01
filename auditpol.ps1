<#
This script configures the advanced audit policies on a target system for CIS.

References:
CIS: https://learn.cisecurity.org/benchmarks
Change registry keys: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkForRegKey?view=powershell-7.2
Change audit policies: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol

NOTE: There can be an issue with this script. The script returns that all the settings are applied, but the settings are not applied at all!'In that case, deploying these settings via a Domain Polocy might be a better solution.

#>



<#
Function for applying the registry values denfined in the registry key section of the script.
Must take the registy path, the name of the registry key, the desired value and the registy value type.

This function also checks if the registry key already exists, of not the registy key will be created.
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

#Sets key for being able to change the advanced audit policy.
checkForRegKey  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" "SCENoApplyLegacyAuditPolicy" 1 DWord -Force

#17.1.1 (L1) Ensure 'Audit Credential Validation' is set to 'Success and Failure' (Automated) 
Auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

#17.2.1 (L1) Ensure 'Audit Application Group Management' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable

#17.2.2 (L1) Ensure 'Audit Security Group Management' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Security Group Management" /success:enable

#17.2.3 (L1) Ensure 'Audit User Account Management' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

#17.3.1 (L1) Ensure 'Audit PNP Activity' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Plug and Play Events" /success:enable

#17.3.2 (L1) Ensure 'Audit Process Creation' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Process Creation" /success:enable

#17.5.1 (L1) Ensure 'Audit Account Lockout' is set to include 'Failure' (Automated)
Auditpol /set /subcategory:"Account Lockout" /failure:enable

#17.5.2 (L1) Ensure 'Audit Group Membership' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Group Membership" /success:enable

#17.5.3 (L1) Ensure 'Audit Logoff' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Logoff" /success:enable

#17.5.4 (L1) Ensure 'Audit Logon' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable

#17.5.5 (L1) Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

#17.5.6 (L1) Ensure 'Audit Special Logon' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Special Logon" /success:enable

#17.6.1 (L1) Ensure 'Audit Detailed File Share' is set to include 'Failure' (Automated)
Auditpol /set /subcategory:"Detailed File Share" /failure:enable

#17.6.2 (L1) Ensure 'Audit File Share' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"File Share" /success:enable /failure:enable

#17.6.3 (L1) Ensure 'Audit Other Object Access Events' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

#17.6.4 (L1) Ensure 'Audit Removable Storage' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

#17.7.1 (L1) Ensure 'Audit Audit Policy Change' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Audit Policy Change" /success:enable

#17.7.2 (L1) Ensure 'Audit Authentication Policy Change' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Authentication Policy Change" /success:enable

#17.7.3 (L1) Ensure 'Audit Authorization Policy Change' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Authorization Policy Change" /success:enable

#17.7.4 (L1) Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable

#17.7.5 (L1) Ensure 'Audit Other Policy Change Events' is set to include 'Failure' (Automated)
Auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable

#17.8.1 (L1) Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable

#17.9.1 (L1) Ensure 'Audit IPsec Driver' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable

#17.9.2 (L1) Ensure 'Audit Other System Events' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable

#17.9.3 (L1) Ensure 'Audit Security State Change' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Security State Change" /success:enable

#17.9.4 (L1) Ensure 'Audit Security System Extension' is set to include 'Success' (Automated)
Auditpol /set /subcategory:"Security System Extension" /success:enable

#17.9.5 (L1) Ensure 'Audit System Integrity' is set to 'Success and Failure' (Automated)
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
