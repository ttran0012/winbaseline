#Requires -RunAsAdministrator
# Step 0 (host): turn on Hyper-V. Restart Windows afterward.

$feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
if ($feature.State -eq 'Enabled') {
  Write-Host 'Hyper-V is already enabled. Continue with 1-New-LabHost.ps1.' -ForegroundColor Green
  return
}

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart | Out-Null
Write-Host 'Hyper-V enabled. Restart Windows, then run 1-New-LabHost.ps1.' -ForegroundColor Yellow
