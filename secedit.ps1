<#
This script configures the target Windows 11 Client for compliance with CIS-benchmarks, specifically for the legacy local policies.
Some recommendations consists of a specific time period, for example 180 to 365 days. These entries can be modified by using the variables in this script.
The standaard values in this script are the first value mentioned in the range. 
For example between 180 and 365 days, 180 days is configured as the default value.
For Not fewer than 10 days, 10 days is configured as the default value.
For not longer than 15 days, 15 days is configured as the default value. 

Reference:
   CIS: https://learn.cisecurity.org/benchmarks
   Used methods references: https://stackoverflow.com/questions/55774478/enforce-password-complexity-on-windows-using-powershell
   net accounts: https://stackoverflow.com/questions/60117943/powershell-script-to-report-account-lockout-policy-settings

#>


<#
Function to export the current local policy secedit cfg and convert the cfg file into
an editable .txt file.
#>
Function Parse-SecPol($CfgFile){ 
    secedit /export /cfg "$CfgFile" | out-null
    $obj = New-Object psobject
    $index = 0
    $contents = Get-Content $CfgFile -raw
    [regex]::Matches($contents,"(?<=\[)(.*)(?=\])") | %{
        $title = $_
        [regex]::Matches($contents,"(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{
            $section = new-object psobject
            $_.value -split "\r\n" | ?{$_.length -gt 0} | %{
                $value = [regex]::Match($_,"(?<=\=).*").value
                $name = [regex]::Match($_,".*(?=\=)").value
                $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
            }
            $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
        }
        $index += 1
    }
    return $obj
}

<#
Applies the desired policy configuration
#>
Function Set-SecPol($Object, $CfgFile){
   $SecPol.psobject.Properties.GetEnumerator() | %{
        "[$($_.Name)]"
        $_.Value | %{
            $_.psobject.Properties.GetEnumerator() | %{
                "$($_.Name)=$($_.Value)"
            }
        }
    } | out-file $CfgFile -ErrorAction Stop
    secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile" #/areas SECURITYPOLICY
}

<#
Adds lockoutduration and resettolockout to the secedit config before export.
Not having this command will result in the failure the of #1.2.1 and #1.2.3 rules.
#>
net accounts | out-null

<#
#Initialize secedit policy editable .txt file name
#>

$CfgFileName = "SecEditTest"


<#
Export current secedit cfg confuguration and export a policy as a txt file and put this in a variable. 
This variable is used later in the scripts.
#>

$SecPol = Parse-SecPol -CfgFile $CfgFileName

<#
Customize the values of the variables used in this script here.

Default values:

$enableAdminAccount = 0 
$enableGuestAccount = 0

$passwordHistorySize = 24
$maximumPasswordAge = 365
$minimumPasswordAge = 1
$minimumPasswordLength = 14

$lockoutBadCount = 5
$lockoutDurationValue = 15
$resetoLockoutCount = 15

#>


<#
Enable or disable the Admin and Guest accounts.
0 - Disabled
1 - Enabled
#>
$enableAdminAccount = 0 
$enableGuestAccount = 0

<#
Password policy values.
#>
$passwordHistorySize = 24
$maximumPasswordAge = 365
$minimumPasswordAge = 1
$minimumPasswordLength = 14

<#
Account lockout values.
#>
$lockoutBadCount = 5
$lockoutDurationValue = 15
$resetoLockoutCount = 15

<#
Enable or disable the Admin and Guest accounts.
0 - Disabled
1 - Enabled
#>
$enableAdminAccount = 0 
$enableGuestAccount = 0

<#
Apply the desired configuration.

syntax: $seceditExportName.'Section of policy'.Policy = value
example: $SecPol.'System Access'.PasswordHistorySize = 10
#>

#1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)' (Automated)
$SecPol.'System Access'.PasswordHistorySize = $passwordHistorySize

#1.1.2 (L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0' (Automated)
$SecPol.'System Access'.MaximumPasswordAge = $maximumPasswordAge

#1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'(Automated)
$SecPol.'System Access'.MinimumPasswordAge = $minimumPasswordAge

# 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)' (Automated)
$SecPol.'System Access'.MinimumPasswordLength = $minimumPasswordLength

#1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled' (Automated)
$SecPol.'System Access'.PasswordComplexity = "1"

#1.1.7 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled' (Automated)
$SecPol.'System Access'.ClearTextPassword = "0"

#1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)' (Automated)
$SecPol.'System Access'.LockoutDuration = $($lockoutDurationValue)

#1.2.2 (L1) Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0' (Automated)
$SecPol.'System Access'.LockoutBadCount = $($lockoutBadCount)

#1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' (Automated)
$SecPol.'System Access'.ResetLockoutCount = $($resetoLockoutCount)

#2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled' (Automated)
$SecPol.'System Access'.EnableAdminAccount = $($enableAdminAccount)

#2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled' (Automated)
$SecPol.'System Access'.EnableGuestAccount = $($enableGuestAccount)

# #2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One' (Automated)
# #$secPol.'Privilege Rights'.SeTrustedCredManAccessPrivilege = "[]" Must be empty, can be skipped.

# #2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users' (Automated)
# $secPol.'Privilege Rights'.SeNetworkLogonRight = "Administrators, Remote Desktop Users"

# #2.2.3 (L1) Ensure 'Act as part of the operating system' is set to 'No One' (Automated)
# #$secPol.'Privilege Rights'.SeTcbPrivilege = "[]" must be empty, can be skipped

# #2.2.4 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE' (Automated)
# $secPol.'Privilege Rights'.SeIncreaseQuotaPrivilege = "Administrators, LOCAL SERVICE, NETWORK SERVICE"

# #2.2.5 (L1) Ensure 'Allow log on locally' is set to 'Administrators, Users' (Automated)
# $secPol.'Privilege Rights'.SeInteractiveLogonRight = "Administrators, Users"

# #2.2.6 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'
# $secPol.'Privilege Rights'.SeRemoteInteractiveLogonRight = "Administrators, Users"

# #2.2.7 (L1) Ensure 'Back up files and directories' is set to 'Administrators' (Automated)
# $secPol.'Privilege Rights'.SeBackupPrivilege = "Administrators" 

# #2.2.8 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE' (Automated)
# $secPol.'Privilege Rights'.SeSystemtimePrivilege = "Administrators, LOCAL SERVICE"

# #2.2.9 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users' (Automated)
# $secPol.'Privilege Rights'.SeTimeZonePrivilege = " Administrators, LOCAL SERVICE, Users" 

# #2.2.10 (L1) Ensure 'Create a pagefile' is set to 'Administrators' (Automated)
# #$secPol.'Privilege Rights'.SeCreatePageFilePrivilege = "Adminstrators" #Doesn't work, due to this value being absent from secedit cfg
 
# #2.2.11 (L1) Ensure 'Create a token object' is set to 'No One' (Automated) 
# #$secPol.'Privilege Rights'.SeCreateTokenPrivilege = "[]" #must be empty, can be skipped

# #2.2.12 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (Automated)
# $secPol.'Privilege Rights'.SeCreateGlobalPrivilege = "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"

# #2.2.13 (L1) Ensure 'Create permanent shared objects' is set to 'No One' (Automated)
# #$secPol.'Privilege Rights'.SeCreatePermanentPrivilege ="[]" #must be empty, can be skipped

# #2.2.14 (L1) Configure 'Create symbolic links' (Automated)
# $secPol.'Privilege Rights'.SeCreateSymbolicLinkPrivilege = "Administrators, NT VIRTUAL MACHINE\Virtual Machines"

# #2.2.15 (L1) Ensure 'Debug programs' is set to 'Administrators' (Automated)
# #$secPol.'Privilege Rights'.SeDebugPrivilege = "Administrators" #Doesn't work, due to this value being absent from secedit cfg

# #2.2.17 (L1) Ensure 'Deny log on as a batch job' to include 'Guests' (Automated)
# #$secPol.'Privilege Rights'.SeDenyBatchLogonRight = "Guests" #Doesn't work, due to this value being absent from secedit cfg

# #2.2.18 (L1) Ensure 'Deny log on as a service' to include 'Guests' (Automated)
# #$secPol.'Privilege Rights'.SeDenyServiceLogonRight = "Guests" #Doesn't work, due to this value being absent from secedit cfg

# #2.2.19 (L1) Ensure 'Deny log on locally' to include 'Guests' (Automated)
# #$secPol.'Privilege Rights'.SeDenyInteractiveLogonRight = "Guests" #Value does not exists during Azure image build. Causes the build to fail.

# #2.2.20 (L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests, Local account' (Automated)
# #$secPol.'Privilege Rights'.SeDenyRemoteInteractiveLogonRight = "Guests, Local account" #Doesn't work, due to this value being absent from secedit cfg

# #2.2.21 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (Automated)
# #$secPol.'Privilege Rights'.SeEnableDelegationPrivilege = "[]" #Doesn't work, due to this value being absent from secedit cfg, must be empty can be skipped.

# #2.2.22 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators' (Automated)
# $secPol.'Privilege Rights'.SeRemoteShutdownPrivilege = "Administrators"

# #2.2.23 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE' (Automated)
# $secPol.'Privilege Rights'.SeAuditPrivilege = "LOCAL SERVICE, NETWORK SERVICE"

# #2.2.24 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' (Automated)
# $secPol.'Privilege Rights'.SeImpersonatePrivilege = "Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE"

# #2.2.25 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group' (Automated
# $secPol.'Privilege Rights'.SeIncreaseBasePriorityPrivilege = "Administrators, Window Manager\Window Manager Group"

# #2.2.26 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators' (Automated)
# $secPol.'Privilege Rights'.SeLoadDriverPrivilege = "Administrators"

# #2.2.27 (L1) Ensure 'Lock pages in memory' is set to 'No One' (Automated)
# #$secPol.'Privilege Rights'.SeLockMemoryPrivilege = "[]" #Doesn't work, due to this value being absent from secedit cfg

# #2.2.30 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' (Automated)
# #$secPol.'Privilege Rights'.SeSecurityPrivilege = "Administrators" #Doesn't work, due to this value being absent from secedit cfg

# #2.2.31 (L1) Ensure 'Modify an object label' is set to 'No One' (Automated)
# #$secPol.'Privilege Rights'.SeSecurityPrivilege = "[]" #Doesn't work, due to this value being absent from secedit cfg

# #2.2.32 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators' (Automated)
# #$secPol.'Privilege Rights'.SeRelabelPrivilege = "Administrators" #Doesn't work, due to this value being absent from secedit cfg

# #2.2.33 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators' (Automated)
# $secPol.'Privilege Rights'.SeSystemEnvironmentPrivilege = "Administrators"

# #2.2.34 (L1) Ensure 'Profile single process' is set to 'Administrators' (Automated)
# $secPol.'Privilege Rights'.SeManageVolumePrivilege = "Administrators"

# #2.2.35 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost' (Automated)
# $secPol.'Privilege Rights'.SeProfileSingleProcessPrivilege = "Administrators, NT SERVICE\WdiServiceHost"

# #2.2.36 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE' (Automated)
# $secPol.'Privilege Rights'.SeAssignPrimaryTokenPrivilege = "LOCAL SERVICE, NETWORK SERVICE"

# #2.2.37 (L1) Ensure 'Restore files and directories' is set to 'Administrators' (Automated)
# $secPol.'Privilege Rights'.SeRestorePrivilege = "Administrators"

# #2.2.38 (L1) Ensure 'Shut down the system' is set to 'Administrators, Users' (Automated)
# $secPol.'Privilege Rights'.SeShutdownPrivilege = "Administrators, Users"

# #2.2.39 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators' (Automated)
# $secPol.'Privilege Rights'.SeTakeOwnershipPrivilege = "Administrators"


<#
Apply the modifications made in the .txt file to the policy configuration.
#>
Set-SecPol -Object $SecPol -CfgFile $CfgFileName

