#Requires -RunAsAdministrator
# Run inside WS01 only (after it joins the domain). Applies the settings the GPO does not:
# audit policy (AUD-001 to AUD-007), Guest disabled (ACCT-001), and the built-in
# Administrator renamed to "locadm" (ACCT-002; "locadm" is on the GRP-001 approved list).

$ErrorActionPreference = 'Stop'
$auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'

# subcategory GUIDs match the baseline, so this works on any Windows language
$audit = @(
  @('{0CCE923F-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # Credential Validation
  @('{0CCE9237-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Security Group Management
  @('{0CCE9235-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # User Account Management
  @('{0CCE9217-69AE-11D9-BED3-505054503030}', '/failure:enable')                     # Account Lockout
  @('{0CCE9215-69AE-11D9-BED3-505054503030}', '/success:enable', '/failure:enable')   # Logon
  @('{0CCE921B-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Special Logon
  @('{0CCE922F-69AE-11D9-BED3-505054503030}', '/success:enable')                     # Audit Policy Change
)
foreach ($a in $audit) {
  & $auditpol /set "/subcategory:$($a[0])" @($a[1..($a.Count - 1)]) | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($a[0])" }
}
Write-Host 'Audit policy applied (7 subcategories)'

$guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
Disable-LocalUser -SID $guest.SID
$admin = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }
if ($admin.Name -ne 'locadm') { Rename-LocalUser -SID $admin.SID -NewName 'locadm' }
Write-Host 'Guest disabled; built-in Administrator renamed to locadm' -ForegroundColor Green
