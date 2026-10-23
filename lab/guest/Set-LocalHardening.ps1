#Requires -RunAsAdministrator
# Run inside WS01 only (after it joins the domain). Applies the settings the GPO does not:
# audit policy (AUD-001 to AUD-017), Guest disabled (ACCT-001), and the built-in
# Administrator renamed to "locadm" (ACCT-002; "locadm" is on the GRP-001 approved list).

$ErrorActionPreference = 'Stop'
$auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'

# subcategory GUIDs match the baseline, so this works on any Windows language
$audit = @(
  ,@('{0CCE923F-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # Credential Validation
  ,@('{0CCE9237-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Security Group Management
  ,@('{0CCE9235-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # User Account Management
  ,@('{0CCE9217-69AE-11D9-BED3-505054503030}', '/failure:enable')                     # Account Lockout
  ,@('{0CCE9215-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # Logon
  ,@('{0CCE921B-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Special Logon
  ,@('{0CCE922F-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Audit Policy Change
  # added in baseline 0.3.0 (AUD-008 to AUD-017)
  ,@('{0CCE9216-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Logoff
  ,@('{0CCE921C-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # Other Logon/Logoff Events
  ,@('{0CCE9249-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Group Membership
  ,@('{0CCE922B-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Process Creation
  ,@('{0CCE9230-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Authentication Policy Change
  ,@('{0CCE9228-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # Sensitive Privilege Use
  ,@('{0CCE9210-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Security State Change
  ,@('{0CCE9211-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Security System Extension
  ,@('{0CCE9212-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # System Integrity
  ,@('{0CCE9245-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # Removable Storage
)
foreach ($a in $audit) {
  & $auditpol /set "/subcategory:$($a[0])" @($a[1..($a.Count - 1)]) | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($a[0])" }
}
Write-Host "Audit policy applied ($($audit.Count) subcategories)"

$guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
Disable-LocalUser -SID $guest.SID
$admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
if ($admin.Name -ne 'locadm') { Rename-LocalUser -SID $admin.SID -NewName 'locadm' }
Write-Host 'Guest disabled; built-in Administrator renamed to locadm' -ForegroundColor Green
