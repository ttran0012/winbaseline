#Requires -RunAsAdministrator
# Run on the computer that hosts the dashboard (WS01 in the lab). Shares its results folder
# so other computers can save scheduled-scan evidence there, one folder per computer.
#
# Permissions are least-privilege: each computer account (for example LAB\WS02$) can write
# only to its own folder, Domain Admins have full control, and no other account has access.
# A computer cannot read or change another computer's evidence.
#
#   .\New-EvidenceShare.ps1 -Computers DC01,WS02,SRV01

param(
  [Parameter(Mandatory)] [string[]] $Computers,
  [string] $Path = 'C:\WinBaseline\results',
  [string] $ShareName = 'WinBaselineEvidence',
  [string] $Domain = 'LAB'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Path | Out-Null

# Folder permissions: no inheritance from C:\WinBaseline; admins and SYSTEM full control;
# domain computers may only open the share root (this folder only, no file access).
& icacls $Path /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "$Domain\Domain Admins:(OI)(CI)F" "$Domain\Domain Computers:(RX)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed on $Path" }

foreach ($c in $Computers) {
  $folder = Join-Path $Path $c.ToUpper()
  New-Item -ItemType Directory -Force -Path $folder | Out-Null
  # the computer's own account may create and change files in its own folder only
  & icacls $folder /grant "$Domain\$($c.ToUpper())`$:(OI)(CI)M" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls failed on $folder" }
  Write-Host "  $folder  writable by $Domain\$($c.ToUpper())`$"
}

if (-not (Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue)) {
  New-SmbShare -Name $ShareName -Path $Path -ChangeAccess "$Domain\Domain Computers" -FullAccess "$Domain\Domain Admins" | Out-Null
}
# allow other computers to reach the share
Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Out-Null

Write-Host "Evidence share ready: \\$env:COMPUTERNAME\$ShareName" -ForegroundColor Green
Write-Host "Next, on each computer: C:\WinBaseline\Install-ScanTask.ps1 -Share \\$env:COMPUTERNAME\$ShareName"
