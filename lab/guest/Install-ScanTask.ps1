#Requires -RunAsAdministrator
# Run on each computer that should scan itself (DC01, WS02, SRV01 in the lab). Registers a
# scheduled task that runs driftscan locally as SYSTEM - so all checks, including audit
# policy, can be read - and saves the evidence to this computer's folder on the evidence
# share. Nothing listens on the network and Remote Registry is not needed.
#
#   .\Install-ScanTask.ps1 -Share \\WS01\WinBaselineEvidence
#   .\Install-ScanTask.ps1 -Remove            (unregisters the task)
#
# The baseline is chosen from what this computer is, unless -Baseline names a file:
#   domain controller -> windows-server-2022-dc-baseline.yaml
#   other server      -> windows-server-2025-ms-baseline.yaml
#   workstation       -> windows11-baseline.yaml

param(
  [string] $Share,
  [string] $At = '06:00',
  [string] $Baseline,
  [switch] $Remove
)

$ErrorActionPreference = 'Stop'
$TaskName = 'WinBaseline Drift Scan'
$TaskPath = '\WinBaseline\'

if ($Remove) {
  Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue
  Write-Host "Removed scheduled task $TaskPath$TaskName"
  return
}
if (-not $Share) { throw 'Pass -Share, for example -Share \\WS01\WinBaselineEvidence' }

$exe = 'C:\WinBaseline\driftscan.exe'
if (-not $Baseline) {
  # DomainRole: 0-1 workstation, 2-3 member or standalone server, 4-5 domain controller
  $role = (Get-CimInstance Win32_ComputerSystem).DomainRole
  $Baseline = if ($role -ge 4) { 'windows-server-2022-dc-baseline.yaml' }
              elseif ($role -ge 2) { 'windows-server-2025-ms-baseline.yaml' }
              else { 'windows11-baseline.yaml' }
}
$baseline = if ([IO.Path]::IsPathRooted($Baseline)) { $Baseline } else { Join-Path 'C:\WinBaseline\baseline' $Baseline }
Write-Host "Baseline: $baseline"
foreach ($f in $exe, $baseline) { if (-not (Test-Path $f)) { throw "Missing $f - copy the lab files to this computer first" } }
$out = Join-Path $Share $env:COMPUTERNAME

$action    = New-ScheduledTaskAction -Execute $exe -Argument "-baseline `"$baseline`" -out `"$out`"" -WorkingDirectory 'C:\WinBaseline'
$daily     = New-ScheduledTaskTrigger -Daily -At $At
$startup   = New-ScheduledTaskTrigger -AtStartup
$startup.Delay = 'PT5M'      # give the network time to come up after a restart
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $action -Trigger $daily, $startup `
  -Principal $principal -Settings $settings -Description 'Read-only configuration drift scan; evidence saved to the WinBaseline evidence share.' -Force | Out-Null
Write-Host "Registered $TaskPath$TaskName (daily at $At and 5 minutes after startup), saving to $out"

Write-Host 'Running it once now...'
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
do { Start-Sleep -Seconds 2; $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath $TaskPath } while ((Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath).State -eq 'Running')

# driftscan exit codes: 0 clean, 1 drift, 4 changed since capture -> the scan worked
# 2 nothing could be read or saved, 3 evidence verification failed -> something is wrong
$code = $info.LastTaskResult
$meaning = switch ($code) { 0 { 'clean' } 1 { 'drift found' } 4 { 'changed since capture' } 2 { 'scan could not run or save' } 3 { 'evidence verification failed' } default { 'unexpected' } }
$color = if ($code -in 0, 1, 4) { 'Green' } else { 'Red' }
Write-Host "First run finished with exit code $code ($meaning)" -ForegroundColor $color
if ($code -notin 0, 1, 4) {
  Write-Host "Check that $Share is reachable and that this computer's account can write to $out."
}
