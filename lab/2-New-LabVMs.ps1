#Requires -RunAsAdministrator
# Step 2 (host): create the lab VMs on Z: from ISOs. Only pass the ISOs for VMs that
# still need to be created; existing VMs are skipped.
# Examples:
#   all at once: .\2-New-LabVMs.ps1 -ServerIso <server2022>.iso -ClientIso <win11>.iso -MemberServerIso <server2025>.iso
#   only SRV01:  .\2-New-LabVMs.ps1 -MemberServerIso Z:\Hyper-V\ISO\<server2025>.iso

param(
  [string] $ServerIso,          # Windows Server 2022 for DC01
  [string] $ClientIso,          # Windows 11 Enterprise for WS01 and WS02
  [string] $MemberServerIso     # Windows Server 2025 for SRV01
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lab-config.ps1"

foreach ($iso in @($ServerIso, $ClientIso, $MemberServerIso) | Where-Object { $_ }) {
  if (-not (Test-Path $iso)) { throw "ISO not found: $iso" }
}

foreach ($vm in $LabVMs) {
  $name = $vm.Name
  if (Get-VM -Name $name -ErrorAction SilentlyContinue) {
    Write-Host "$name already exists, skipping"
    continue
  }
  $iso = switch ($vm.OS) { 'server' { $ServerIso } 'member' { $MemberServerIso } default { $ClientIso } }
  if (-not $iso) {
    $flag = switch ($vm.OS) { 'server' { '-ServerIso' } 'member' { '-MemberServerIso' } default { '-ClientIso' } }
    Write-Host "$name skipped (pass $flag to create it)"
    continue
  }
  $vhd = Join-Path "$LabRoot\$name" "$name.vhdx"
  New-VM -Name $name -Generation 2 -Path $LabRoot -SwitchName $SwitchName `
    -MemoryStartupBytes ($vm.RamGB * 1GB) -NewVHDPath $vhd -NewVHDSizeBytes ($vm.DiskGB * 1GB) | Out-Null

  Set-VM -Name $name -ProcessorCount 2 -StaticMemory -AutomaticCheckpointsEnabled $false -CheckpointType Standard
  Enable-VMIntegrationService -VMName $name -Name 'Guest Service Interface'   # lets Copy-VMFile send files in

  # Windows 11 requires TPM 2.0 and Secure Boot
  Set-VMKeyProtector -VMName $name -NewLocalKeyProtector
  Enable-VMTPM -VMName $name

  $dvd = Add-VMDvdDrive -VMName $name -Path $iso -Passthru
  Set-VMFirmware -VMName $name -FirstBootDevice $dvd

  Write-Host "Created $name ($($vm.OS), $($vm.RamGB) GB RAM, $($vm.DiskGB) GB disk) in $LabRoot\$name"
}

Write-Host ''
Write-Host 'Next: start each VM and install Windows (press a key at "Press any key to boot from CD or DVD").' -ForegroundColor Green
Write-Host 'Name the local account created during Windows 11 setup "itadmin" (it is on the approved admin list).' -ForegroundColor Green
