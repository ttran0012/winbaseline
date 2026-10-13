#Requires -RunAsAdministrator
# Step 1 (host): store VMs on Z:, create the isolated lab switch, and give the VMs
# internet access through NAT (needed for Windows activation of the evaluations and updates).

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\lab-config.ps1"

if (-not (Test-Path 'Z:\')) { throw 'Drive Z: was not found.' }
New-Item -ItemType Directory -Force -Path $LabRoot, "$LabRoot\Virtual Hard Disks" | Out-Null
Set-VMHost -VirtualMachinePath $LabRoot -VirtualHardDiskPath "$LabRoot\Virtual Hard Disks"
Write-Host "Default VM storage: $LabRoot"

if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
  New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
  Write-Host "Created internal switch '$SwitchName'"
}

$hostAdapter = Get-NetAdapter -Name "vEthernet ($SwitchName)"
if (-not (Get-NetIPAddress -InterfaceIndex $hostAdapter.ifIndex -IPAddress $HostIP -ErrorAction SilentlyContinue)) {
  New-NetIPAddress -InterfaceIndex $hostAdapter.ifIndex -IPAddress $HostIP -PrefixLength 24 | Out-Null
  Write-Host "Host address on the lab switch: $HostIP"
}

if (-not (Get-NetNat -Name $NatName -ErrorAction SilentlyContinue)) {
  $other = Get-NetNat -ErrorAction SilentlyContinue
  if ($other) {
    Write-Warning "Another NAT network already exists ($($other.Name)). Windows allows only one; the lab will work without internet."
  } else {
    New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $Subnet | Out-Null
    Write-Host "NAT enabled for $Subnet"
  }
}

Write-Host 'Host ready. Next: download the evaluation ISOs, then run 2-New-LabVMs.ps1.' -ForegroundColor Green
