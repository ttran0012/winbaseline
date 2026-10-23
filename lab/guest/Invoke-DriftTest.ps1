#Requires -RunAsAdministrator
# 25-change drift detection test (task 4.2). Run inside a lab VM, ideally WS01: it is
# hardened, so almost every check starts COMPLIANT and each change should flip exactly
# one check to DRIFT.
#
#   Phase 1  clean scan: records the starting status of every check
#   Phase 2  apply 25 deliberate changes (one per check), recording each original value
#   Phase 3  scan again: every targeted check must be DRIFT (detection), and no other
#            check may change status (false alarm)
#   Phase 4  restore every change (always runs), scan again, and confirm every check is
#            back to its Phase 1 status
#
# Output: a PASS/FAIL table, drift-test-<time>\results.csv, and a summary line.
# Evidence is written to drift-test-<time>\evidence, so the main results chain is untouched.
# Take a checkpoint first:  Checkpoint-VM -Name WS01 -SnapshotName "Before drift test"

$ErrorActionPreference = 'Stop'
$dir      = $PSScriptRoot
$exe      = Join-Path $dir 'driftscan.exe'
$baseline = Join-Path $dir 'baseline\windows11-baseline.yaml'
$runDir   = Join-Path $dir ("drift-test-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$evidence = Join-Path $runDir 'evidence'
$auditpol = Join-Path $env:SystemRoot 'System32\auditpol.exe'
$adminsSid = 'S-1-5-32-544'
$testUser  = 'drifttest-vendor'
$fakeApp   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinBaselineDriftTest'

if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { throw 'Run this on a client or member server, not on the domain controller.' }
foreach ($f in $exe, $baseline) { if (-not (Test-Path $f)) { throw "Missing $f" } }
New-Item -ItemType Directory -Force $evidence | Out-Null

function Scan {
  & $exe -baseline $baseline -out $evidence | Out-Null
  $code = $LASTEXITCODE
  $file = Get-ChildItem $evidence -Filter 'scan-*.json' | Sort-Object Name | Select-Object -Last 1
  $json = Get-Content -Raw $file.FullName | ConvertFrom-Json
  $status = @{}; $actual = @{}
  foreach ($r in $json.results) { $status[$r.id] = $r.status; $actual[$r.id] = $r.actual }
  [pscustomobject]@{ Code = $code; Status = $status; Actual = $actual; File = $file.Name }
}

# ---------- reversible change helpers: each returns a restore scriptblock ----------
function Set-RegChange($path, $name, [int]$value) {
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null; $created = $true } else { $created = $false }
  $old = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
  $had = $null -ne $old
  $oldValue = if ($had) { $old.$name } else { $null }
  Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord
  { if ($had) { Set-ItemProperty -Path $path -Name $name -Value $oldValue -Type DWord }
    else { Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue }
    if ($created) { Remove-Item -Path $path -Force -ErrorAction SilentlyContinue } }.GetNewClosure()
}
function Set-ServiceChange($name) {
  $svc = Get-CimInstance Win32_Service -Filter "Name='$name'"
  if (-not $svc) { throw "service $name is not installed" }
  $map = @{ Auto = 'auto'; Manual = 'demand'; Disabled = 'disabled'; Boot = 'boot'; System = 'system' }
  $old = $map[[string]$svc.StartMode]
  & sc.exe config $name start= demand | Out-Null
  { & sc.exe config $name start= $old | Out-Null }.GetNewClosure()
}
function Set-AuditChange($guid) {
  $row = (& $auditpol /get "/subcategory:$guid" /r | Where-Object { $_ -match ',' } | ConvertFrom-Csv) | Select-Object -First 1
  if (-not $row) { throw "could not read audit setting $guid" }
  $was = $row.'Inclusion Setting'
  & $auditpol /set "/subcategory:$guid" /success:disable /failure:disable | Out-Null
  { $s = if ($was -match 'Success') { 'enable' } else { 'disable' }
    $f = if ($was -match 'Failure') { 'enable' } else { 'disable' }
    & $auditpol /set "/subcategory:$guid" "/success:$s" "/failure:$f" | Out-Null }.GetNewClosure()
}
function Set-FirewallChange($profile, $policyName) {
  $policy = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$policyName"
  if ($null -ne (Get-ItemProperty $policy -Name EnableFirewall -ErrorAction SilentlyContinue)) {
    return Set-RegChange $policy 'EnableFirewall' 0      # Group Policy value wins, so change it there
  }
  $was = (Get-NetFirewallProfile -Profile $profile).Enabled
  Set-NetFirewallProfile -Profile $profile -Enabled False
  { Set-NetFirewallProfile -Profile $profile -Enabled $was }.GetNewClosure()
}

$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$changes = @(
  # ----- registry (12)
  @{ Id = 'REG-002'; What = 'UAC admin prompt set to "elevate without prompting on secure desktop" (5)'; Do = { Set-RegChange $sys 'ConsentPromptBehaviorAdmin' 5 } }
  @{ Id = 'REG-003'; What = 'CTRL+ALT+DEL no longer required';                 Do = { Set-RegChange $sys 'DisableCAD' 1 } }
  @{ Id = 'REG-004'; What = 'Inactivity lock raised to 3600 seconds';          Do = { Set-RegChange $sys 'InactivityTimeoutSecs' 3600 } }
  @{ Id = 'REG-005'; What = 'Anonymous SAM account enumeration allowed';       Do = { Set-RegChange $lsa 'RestrictAnonymousSAM' 0 } }
  @{ Id = 'REG-006'; What = 'Anonymous share enumeration allowed';             Do = { Set-RegChange $lsa 'RestrictAnonymous' 0 } }
  @{ Id = 'REG-007'; What = 'LAN Manager auth level lowered to 3';             Do = { Set-RegChange $lsa 'LmCompatibilityLevel' 3 } }
  @{ Id = 'REG-008'; What = 'LM hash storage allowed';                         Do = { Set-RegChange $lsa 'NoLMHash' 0 } }
  @{ Id = 'REG-009'; What = 'WDigest plaintext credential caching enabled';   Do = { Set-RegChange 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 1 } }
  @{ Id = 'REG-010'; What = 'SMB server signing no longer required';           Do = { Set-RegChange 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RequireSecuritySignature' 0 } }
  @{ Id = 'REG-011'; What = 'SMB client signing no longer required';           Do = { Set-RegChange 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 0 } }
  @{ Id = 'REG-012'; What = 'SMBv1 server registry setting turned on';         Do = { Set-RegChange 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 1 } }
  @{ Id = 'REG-013'; What = 'Autoplay re-enabled for some drive types (0x91)'; Do = { Set-RegChange 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 0x91 } }
  # ----- services (5): start type changed from disabled to manual
  @{ Id = 'SVC-001'; What = 'Routing and Remote Access set to manual';         Do = { Set-ServiceChange 'RemoteAccess' } }
  @{ Id = 'SVC-002'; What = 'SSDP Discovery set to manual';                    Do = { Set-ServiceChange 'SSDPSRV' } }
  @{ Id = 'SVC-003'; What = 'UPnP Device Host set to manual';                  Do = { Set-ServiceChange 'upnphost' } }
  @{ Id = 'SVC-006'; What = 'RPC Locator set to manual';                       Do = { Set-ServiceChange 'RpcLocator' } }
  @{ Id = 'SVC-007'; What = 'Xbox Live Game Save set to manual';               Do = { Set-ServiceChange 'XblGameSave' } }
  # ----- accounts and group (3)
  @{ Id = 'ACCT-001'; What = 'Built-in Guest account enabled'; Do = {
      $g = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }; $was = $g.Enabled
      Enable-LocalUser -SID $g.SID
      { if (-not $was) { Disable-LocalUser -SID $g.SID } }.GetNewClosure() } }
  @{ Id = 'ACCT-002'; What = 'Built-in Administrator renamed back to "Administrator"'; Do = {
      $a = Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }; $was = $a.Name
      if ($was -eq 'Administrator') { throw 'built-in Administrator is not renamed, so this check is already drifting' }
      Rename-LocalUser -SID $a.SID -NewName 'Administrator'
      { Rename-LocalUser -SID $a.SID -NewName $was }.GetNewClosure() } }
  @{ Id = 'GRP-001'; What = "Unapproved account '$testUser' added to Administrators"; Do = {
      New-LocalUser -Name $testUser -NoPassword -Disabled | Out-Null
      Add-LocalGroupMember -SID $adminsSid -Member $testUser
      { Remove-LocalUser -Name $testUser -ErrorAction SilentlyContinue } } }
  # ----- firewall (2)
  @{ Id = 'FW-002'; What = 'Private firewall profile turned off'; Do = { Set-FirewallChange 'Private' 'PrivateProfile' } }
  @{ Id = 'FW-003'; What = 'Public firewall profile turned off';  Do = { Set-FirewallChange 'Public' 'PublicProfile' } }
  # ----- audit policy (2)
  @{ Id = 'AUD-005'; What = 'Logon auditing turned off';               Do = { Set-AuditChange '{0CCE9215-69AE-11D9-BED3-505054503030}' } }
  @{ Id = 'AUD-007'; What = 'Audit Policy Change auditing turned off'; Do = { Set-AuditChange '{0CCE922F-69AE-11D9-BED3-505054503030}' } }
  # ----- installed software (1): a fake uninstall entry, nothing is installed
  @{ Id = 'SW-002'; What = 'Unapproved remote access tool appears installed (fake entry)'; Do = {
      New-Item -Path $fakeApp -Force | Out-Null
      Set-ItemProperty -Path $fakeApp -Name DisplayName -Value 'AnyDesk (WinBaseline drift test)'
      { Remove-Item -Path $fakeApp -Recurse -Force -ErrorAction SilentlyContinue } } }
)
if ($changes.Count -ne 25) { throw "expected 25 changes, found $($changes.Count)" }

Write-Host "25-change drift test on $env:COMPUTERNAME" -ForegroundColor Cyan
Write-Host "Output: $runDir`n"

$restore = [System.Collections.Generic.List[object]]::new()
$applied = @{}
$rows = [System.Collections.Generic.List[object]]::new()
$restoreOK = $false

Write-Host 'Phase 1: clean scan'
$before = Scan
$sw = [Diagnostics.Stopwatch]::StartNew()

try {
  Write-Host 'Phase 2: applying 25 changes'
  foreach ($c in $changes) {
    if ($before.Status[$c.Id] -ne 'COMPLIANT') {
      $applied[$c.Id] = "not testable: already $($before.Status[$c.Id]) before the change"
      continue
    }
    try { $restore.Add(@{ Id = $c.Id; Undo = (& $c.Do) }); $applied[$c.Id] = 'applied' }
    catch { $applied[$c.Id] = "not applied: $($_.Exception.Message)" }
  }

  Write-Host 'Phase 3: scan after changes'
  $after = Scan
  $targets = $changes | ForEach-Object { $_.Id }
  foreach ($c in $changes) {
    $result = if ($applied[$c.Id] -ne 'applied') { 'NOT TESTED' }
              elseif ($after.Status[$c.Id] -eq 'DRIFT') { 'DETECTED' } else { 'MISSED' }
    $rows.Add([pscustomobject]@{ Check = $c.Id; Change = $c.What; Before = $before.Status[$c.Id];
      After = $after.Status[$c.Id]; Actual = $after.Actual[$c.Id]; Result = $result; Note = $(if ($applied[$c.Id] -ne 'applied') { $applied[$c.Id] }) })
  }
  $falseAlarms = @($before.Status.Keys | Where-Object { $targets -notcontains $_ -and $before.Status[$_] -ne $after.Status[$_] } |
    ForEach-Object { "$_ ($($before.Status[$_]) -> $($after.Status[$_]))" })
}
finally {
  Write-Host 'Phase 4: restoring every change'
  $failedRestore = @()
  for ($i = $restore.Count - 1; $i -ge 0; $i--) {
    try { & $restore[$i].Undo } catch { $failedRestore += "$($restore[$i].Id): $($_.Exception.Message)" }
  }
  $restored = Scan
  $mismatch = @($before.Status.Keys | Where-Object { $before.Status[$_] -ne $restored.Status[$_] } |
    ForEach-Object { "$_ ($($before.Status[$_]) -> $($restored.Status[$_]))" })
  $restoreOK = ($failedRestore.Count -eq 0 -and $mismatch.Count -eq 0)
}
$sw.Stop()

$rows | Export-Csv (Join-Path $runDir 'results.csv') -NoTypeInformation
$rows | Format-Table Check, Result, Before, After, Change -AutoSize -Wrap | Out-String -Width 220 | Write-Host

$tested   = @($rows | Where-Object Result -ne 'NOT TESTED').Count
$detected = @($rows | Where-Object Result -eq 'DETECTED').Count
if ($falseAlarms) { Write-Host "False alarms: $($falseAlarms -join '; ')" -ForegroundColor Red }
if ($failedRestore) { Write-Host "Restore errors: $($failedRestore -join '; ')" -ForegroundColor Red }
if ($mismatch) { Write-Host "Not back to the starting state: $($mismatch -join '; ')" -ForegroundColor Red }

$summary = "Detected $detected of $tested changes ($(25 - $tested) not testable), $(@($falseAlarms).Count) false alarms, restore $(if ($restoreOK) { 'OK' } else { 'FAILED' }), $([Math]::Round($sw.Elapsed.TotalSeconds,1)) s"
$summary | Set-Content (Join-Path $runDir 'summary.txt')
$pass = ($detected -eq $tested -and $tested -gt 0 -and @($falseAlarms).Count -eq 0 -and $restoreOK)
Write-Host ''
Write-Host $summary -ForegroundColor $(if ($pass) { 'Green' } else { 'Red' })
Write-Host "Evidence chain: run  $exe -verify -out `"$evidence`""
if (-not $pass) { exit 1 }
