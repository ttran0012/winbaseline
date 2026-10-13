#Requires -RunAsAdministrator
# Smoke test for driftscan inside a lab VM (DC01, WS01, WS02, or SRV01).
#   1. Baseline scan
#   2. Make three deliberate changes:
#        - turn off the Public firewall profile             -> FW-003 should become DRIFT
#        - add a disabled "smoketest-vendor" account to the
#          Administrators group                             -> GRP-001 should become DRIFT
#        - set the UAC admin prompt to the CIS value (2)    -> REG-002 should become COMPLIANT
#   3. Scan again and check each result and the exit code
#   4. Verify the evidence chain
#   5. Edit a COPY of the evidence and confirm verify detects it
#   6. Undo every change (always runs, even if a step fails)
# Evidence goes to a new folder, so the regular results\ chain is not touched.

$ErrorActionPreference = 'Stop'
$dir      = $PSScriptRoot
$exe      = Join-Path $dir 'driftscan.exe'
$baseline = Join-Path $dir 'baseline\windows11-baseline.yaml'
$out      = Join-Path $dir ("smoke-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$vendor   = 'smoketest-vendor'
$isDC     = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4
$uacKey   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$results  = [System.Collections.Generic.List[object]]::new()

function Check($step, $ok, $detail) {
  $results.Add([pscustomobject]@{ Step = $step; Result = $(if ($ok) { 'PASS' } else { 'FAIL' }); Detail = $detail })
  $color = if ($ok) { 'Green' } else { 'Red' }
  Write-Host ("  [{0}] {1} - {2}" -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $step, $detail) -ForegroundColor $color
}
function Scan {
  & $exe -baseline $baseline -out $out | Out-Null
  $code = $LASTEXITCODE
  $file = Get-ChildItem $out -Filter 'scan-*.json' | Sort-Object Name | Select-Object -Last 1
  $json = Get-Content -Raw $file.FullName | ConvertFrom-Json
  $status = @{}; foreach ($r in $json.results) { $status[$r.id] = $r }
  [pscustomobject]@{ Code = $code; Status = $status; Summary = $json.summary }
}

Write-Host "Smoke test on $env:COMPUTERNAME ($(if ($isDC) { 'domain controller' } else { 'member computer' }))" -ForegroundColor Cyan
Write-Host "Evidence folder: $out`n"

# remember the original state so it can be restored
$origFirewall = (Get-NetFirewallProfile -Profile Public).Enabled
$origUac = (Get-ItemProperty $uacKey -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
$adminsSid = 'S-1-5-32-544'

try {
  Write-Host '1. Baseline scan'
  $before = Scan
  Check 'Baseline scan runs' ($before.Status.Count -gt 0) "$($before.Summary.total) checks: $($before.Summary.compliant) compliant, $($before.Summary.drift) drift, $($before.Summary.errors) errors (exit $($before.Code))"

  Write-Host "`n2. Making deliberate changes"
  Set-NetFirewallProfile -Profile Public -Enabled False
  Write-Host '  Public firewall profile turned off'
  if ($isDC) {
    Import-Module ActiveDirectory
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$vendor'")) { New-ADUser -Name $vendor -SamAccountName $vendor -Enabled $false }
    Add-ADGroupMember -Identity $adminsSid -Members $vendor
  } else {
    if (-not (Get-LocalUser -Name $vendor -ErrorAction SilentlyContinue)) { New-LocalUser -Name $vendor -NoPassword -Disabled | Out-Null }
    Add-LocalGroupMember -SID $adminsSid -Member $vendor
  }
  Write-Host "  Disabled account '$vendor' added to Administrators"
  Set-ItemProperty $uacKey -Name ConsentPromptBehaviorAdmin -Value 2 -Type DWord
  Write-Host '  UAC admin prompt set to 2 (CIS value)'

  Write-Host "`n3. Scan after changes"
  $after = Scan
  Check 'FW-003 firewall off detected'      ($after.Status['FW-003'].status -eq 'DRIFT')     "actual: $($after.Status['FW-003'].actual)"
  Check 'GRP-001 vendor admin detected'     ($after.Status['GRP-001'].status -eq 'DRIFT' -and $after.Status['GRP-001'].note -match $vendor) "$($after.Status['GRP-001'].note)"
  Check 'REG-002 fix recognized'            ($after.Status['REG-002'].status -eq 'COMPLIANT') "before: $($before.Status['REG-002'].status), after: $($after.Status['REG-002'].status)"
  Check 'Exit code 1 when drift is found'   ($after.Code -eq 1) "exit $($after.Code)"

  Write-Host "`n4. Evidence chain"
  & $exe -verify -out $out | Out-Null
  Check 'Chain verifies (2 scans)' ($LASTEXITCODE -eq 0) "exit $LASTEXITCODE"

  Write-Host "`n5. Tamper detection (on a copy)"
  $copy = "$out-tampered"
  Copy-Item $out $copy -Recurse
  $victim = Get-ChildItem $copy -Filter 'scan-*.json' | Sort-Object Name | Select-Object -Last 1
  (Get-Content -Raw $victim.FullName).Replace('"status": "DRIFT"', '"status": "COMPLIANT"') | Set-Content -NoNewline $victim.FullName
  $msg = & $exe -verify -out $copy
  Check 'Edited evidence is detected' ($LASTEXITCODE -eq 3) "exit $LASTEXITCODE; $msg"
}
finally {
  Write-Host "`n6. Restoring original settings"
  Set-NetFirewallProfile -Profile Public -Enabled $origFirewall
  if ($null -ne $origUac) { Set-ItemProperty $uacKey -Name ConsentPromptBehaviorAdmin -Value $origUac -Type DWord }
  else { Remove-ItemProperty $uacKey -Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue }
  if ($isDC) {
    if (Get-ADUser -Filter "SamAccountName -eq '$vendor'") { Remove-ADUser -Identity $vendor -Confirm:$false }
  } else {
    if (Get-LocalUser -Name $vendor -ErrorAction SilentlyContinue) { Remove-LocalUser -Name $vendor }
  }
  Write-Host '  Firewall, UAC setting, and test account restored'
}

$failed = @($results | Where-Object Result -eq 'FAIL').Count
Write-Host ''
$results | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
if ($failed) { Write-Host "SMOKE TEST FAILED: $failed of $($results.Count) checks failed" -ForegroundColor Red; exit 1 }
Write-Host "SMOKE TEST PASSED: all $($results.Count) checks passed" -ForegroundColor Green
