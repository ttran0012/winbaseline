#Requires -RunAsAdministrator
# Step 3 (host): copy the guest setup scripts, driftscan.exe, and the baseline into a running VM
# at C:\WinBaseline. Works without networking (uses Hyper-V Guest Services).
# Files are taken from the folder this script is in (Z:\Hyper-V\Winbaseline-Lab):
#   guest\*.ps1, driftscan.exe, baseline\*.yaml
# Example: .\3-Copy-ToLabVM.ps1 -VMName DC01

param([Parameter(Mandatory)] [string[]] $VMName)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$need = @('guest', 'driftscan.exe', 'baseline')
foreach ($n in $need) {
  if (-not (Test-Path (Join-Path $root $n))) { throw "Missing $n in $root" }
}

$files = @(Get-ChildItem "$root\guest\*.ps1") + (Get-Item "$root\driftscan.exe") + @(Get-ChildItem "$root\baseline\*.yaml")
if (Test-Path "$root\hosts.yaml") { $files += Get-Item "$root\hosts.yaml" }   # optional: the lab's approved scan scope
foreach ($name in $VMName) {
  foreach ($f in $files) {
    $dest = if ($f.Extension -eq '.yaml' -and $f.Name -ne 'hosts.yaml') { "C:\WinBaseline\baseline\$($f.Name)" } else { "C:\WinBaseline\$($f.Name)" }
    Copy-VMFile -Name $name -SourcePath $f.FullName -DestinationPath $dest -CreateFullPath -FileSource Host -Force
  }
  Write-Host "Copied $($files.Count) files from $root to $name at C:\WinBaseline" -ForegroundColor Green
}
