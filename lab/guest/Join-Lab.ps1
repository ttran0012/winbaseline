#Requires -RunAsAdministrator
# Run inside each Windows 11 client and the member server. Sets the static IP, renames the
# computer if needed, and joins the lab domain (-Domain, default lab.example.test) in the right OU. Sign in with
# LAB\Administrator when prompted.
#   WS01:  .\Join-Lab.ps1 -Name WS01 -IP 10.10.10.21 -OU Hardened
#   WS02:  .\Join-Lab.ps1 -Name WS02 -IP 10.10.10.22 -OU Default
#   SRV01: .\Join-Lab.ps1 -Name SRV01 -IP 10.10.10.31 -OU Default

param(
  [Parameter(Mandatory)] [ValidateSet('WS01', 'WS02', 'SRV01')] [string] $Name,
  [Parameter(Mandatory)] [string] $IP,
  [Parameter(Mandatory)] [ValidateSet('Hardened', 'Default')] [string] $OU,
  [string] $Domain = 'lab.example.test'
)

$ErrorActionPreference = 'Stop'
$nic = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
Remove-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IP -PrefixLength 24 -DefaultGateway 10.10.10.254 | Out-Null
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses 10.10.10.10

# Earlier lookups through public DNS (used during Windows setup) leave a cached
# "not found" answer for the lab domain, so clear the cache and give DNS a moment.
Clear-DnsClientCache
$found = $false
foreach ($try in 1..10) {
  if (Resolve-DnsName $Domain -Server 10.10.10.10 -DnsOnly -ErrorAction SilentlyContinue) { $found = $true; break }
  Start-Sleep -Seconds 2
}
if (-not $found) {
  ipconfig /all | Select-String 'IPv4 Address|DNS Servers|Default Gateway'
  throw 'Cannot find the domain. Check that DC01 is running at 10.10.10.10 and that "ping 10.10.10.10" works from this computer.'
}
Clear-DnsClientCache

$cred = Get-Credential -Message 'Domain account that can join computers' -UserName 'LAB\Administrator'
$join = @{
  DomainName = $Domain
  Credential = $cred
  OUPath     = "OU=$OU,OU=Lab Computers,$('DC=' + ($Domain -replace '\.', ',DC='))"
}
if ($env:COMPUTERNAME -ne $Name) { $join.NewName = $Name }   # renaming to the current name is an error
Add-Computer @join -Restart
