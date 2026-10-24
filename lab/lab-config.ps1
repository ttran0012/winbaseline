# Shared settings for the WinBaseline Hyper-V lab. Dot-sourced by the host scripts.

$LabRoot   = 'Z:\Hyper-V\WinBaseline-Lab'        # VM configuration and disks
$SwitchName = 'WinBaseline-Lab'                  # internal switch, isolated from the home network
$NatName   = 'WinBaseline-Lab-NAT'
$Subnet    = '10.10.10.0/24'
$HostIP    = '10.10.10.254'                       # host side of the switch; NAT gateway for the VMs
$Domain    = 'lab.example.test'                  # .test is reserved for testing and never clashes with a real domain

# Name, OS (server = DC ISO | client = Windows 11 ISO | member = Server 2025 ISO), IP, RAM (GB), disk (GB), OU
$LabVMs = @(
  @{ Name = 'DC01';  OS = 'server'; IP = '10.10.10.10'; RamGB = 4; DiskGB = 60 }                     # Windows Server 2022, domain controller
  @{ Name = 'WS01';  OS = 'client'; IP = '10.10.10.21'; RamGB = 4; DiskGB = 64; OU = 'Hardened' }   # Windows 11 Enterprise
  @{ Name = 'WS02';  OS = 'client'; IP = '10.10.10.22'; RamGB = 4; DiskGB = 64; OU = 'Default' }    # Windows 11 Enterprise
  @{ Name = 'SRV01'; OS = 'member'; IP = '10.10.10.31'; RamGB = 4; DiskGB = 60; OU = 'Default' }    # Windows Server 2025 member server
)
