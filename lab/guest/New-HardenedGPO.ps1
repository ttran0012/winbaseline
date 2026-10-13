#Requires -RunAsAdministrator
# Run inside DC01 after Set-DC.ps1 has finished. Creates a Group Policy Object that applies
# the baseline's registry, service, and firewall settings to the Hardened OU (WS01).
# WS02 in the Default OU keeps Windows defaults, so the two clients can be compared.
# Audit policy and the administrator rename are applied locally by Set-LocalHardening.ps1.

$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable GroupPolicy)) {
  Install-WindowsFeature GPMC | Out-Null   # Server Core may not include the Group Policy tools
}
Import-Module GroupPolicy
$GpoName = 'WinBaseline - CIS Hardened'
$Target = 'OU=Hardened,OU=Lab Computers,DC=lab,DC=atlas-tech,DC=test'

$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if (-not $gpo) {
  $gpo = New-GPO -Name $GpoName -Comment 'Applies the WinBaseline v0.2.0 settings for drift testing'
  New-GPLink -Name $GpoName -Target $Target | Out-Null
}

function Set-Dword($key, $name, $value) {
  Set-GPRegistryValue -Name $GpoName -Key "HKLM\$key" -ValueName $name -Type DWord -Value $value | Out-Null
}

# registry checks (REG-001 to REG-013)
$sys = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-Dword $sys EnableLUA 1
Set-Dword $sys ConsentPromptBehaviorAdmin 2
Set-Dword $sys DisableCAD 0
Set-Dword $sys InactivityTimeoutSecs 900
$lsa = 'SYSTEM\CurrentControlSet\Control\Lsa'
Set-Dword $lsa RestrictAnonymousSAM 1
Set-Dword $lsa RestrictAnonymous 1
Set-Dword $lsa LmCompatibilityLevel 5
Set-Dword $lsa NoLMHash 1
Set-Dword 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0
Set-Dword 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' RequireSecuritySignature 1
Set-Dword 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' SMB1 0
Set-Dword 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' RequireSecuritySignature 1
Set-Dword 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 255

# services (SVC-001 to SVC-007): start type 4 = disabled, applied at the next restart
foreach ($svc in 'RemoteAccess', 'SSDPSRV', 'upnphost', 'icssvc', 'sshd', 'RpcLocator', 'XblGameSave') {
  Set-Dword "SYSTEM\CurrentControlSet\Services\$svc" Start 4
}

# firewall (FW-001 to FW-003)
foreach ($p in 'DomainProfile', 'PrivateProfile', 'PublicProfile') {
  Set-Dword "SOFTWARE\Policies\Microsoft\WindowsFirewall\$p" EnableFirewall 1
}

Write-Host "GPO '$GpoName' linked to the Hardened OU. On WS01 run: gpupdate /force, then restart." -ForegroundColor Green
