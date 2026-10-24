#Requires -RunAsAdministrator
# Run inside DC01 three times; each run does the next phase and restarts when needed.
#   Run 1: set the static IP and rename to DC01 (restarts)
#   Run 2: install Active Directory and create the lab forest (restarts)
#   Run 3: create the lab OUs and the itadmin account
# Pass -Domain to use another domain name; the default is lab.example.test.

param([string] $Domain = 'lab.example.test')

$ErrorActionPreference = 'Stop'
$DomainDN = 'DC=' + ($Domain -replace '\.', ',DC=')

if ($env:COMPUTERNAME -ne 'DC01') {
  $nic = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1
  Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
  Remove-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress 10.10.10.10 -PrefixLength 24 -DefaultGateway 10.10.10.254 | Out-Null
  Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses 127.0.0.1, 1.1.1.1
  Write-Host 'Static IP set to 10.10.10.10. Renaming to DC01 and restarting...'
  Rename-Computer -NewName DC01 -Restart
  return
}

$role = (Get-CimInstance Win32_ComputerSystem).DomainRole   # 4 or 5 = domain controller
if ($role -lt 4) {
  Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
  $dsrm = Read-Host -AsSecureString 'Choose a Directory Services Restore Mode (DSRM) password'
  Write-Host "Creating forest $Domain. The server restarts when finished; sign in as LAB\Administrator."
  Install-ADDSForest -DomainName $Domain -DomainNetbiosName LAB -InstallDns `
    -SafeModeAdministratorPassword $dsrm -Force
  return
}

Import-Module ActiveDirectory
if (-not (Get-ADOrganizationalUnit -Filter "Name -eq 'Lab Computers'" -ErrorAction SilentlyContinue)) {
  New-ADOrganizationalUnit -Name 'Lab Computers' -Path $DomainDN
  New-ADOrganizationalUnit -Name 'Hardened' -Path "OU=Lab Computers,$DomainDN"
  New-ADOrganizationalUnit -Name 'Default'  -Path "OU=Lab Computers,$DomainDN"
  Write-Host 'Created OUs: Lab Computers\Hardened (WS01) and Lab Computers\Default (WS02)'
}
if (-not (Get-ADUser -Filter "SamAccountName -eq 'itadmin'" -ErrorAction SilentlyContinue)) {
  $pw = Read-Host -AsSecureString 'Choose a password for LAB\itadmin'
  New-ADUser -Name 'IT Admin' -SamAccountName itadmin -UserPrincipalName "itadmin@$Domain" `
    -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true
  Add-ADGroupMember -Identity 'Domain Admins' -Members itadmin
  Write-Host 'Created LAB\itadmin (Domain Admins)'
}
Write-Host 'Domain controller ready. Next: run New-HardenedGPO.ps1 here, then Join-Lab.ps1 on WS01 and WS02.' -ForegroundColor Green
