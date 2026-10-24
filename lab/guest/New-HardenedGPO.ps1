#Requires -RunAsAdministrator
# Run inside DC01 after Set-DC.ps1 has finished. Creates a Group Policy Object that applies
# the baseline's registry, service, and firewall settings to the Hardened OU (WS01).
# WS02 in the Default OU keeps Windows defaults, so the two clients can be compared.
# Audit policy and the administrator rename are applied locally by Set-LocalHardening.ps1.

param([string] $Domain = 'lab.example.test')   # the lab domain created by Set-DC.ps1

$ErrorActionPreference = 'Stop'
if (-not (Get-Module -ListAvailable GroupPolicy)) {
  Install-WindowsFeature GPMC | Out-Null   # Server Core may not include the Group Policy tools
}
Import-Module GroupPolicy
$GpoName = 'WinBaseline - CIS Hardened'
$Target = 'OU=Hardened,OU=Lab Computers,DC=' + ($Domain -replace '\.', ',DC=')

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

# registry checks added in baseline 0.3.0 (REG-015 to REG-048; REG-049, the SMBv1 client
# driver, is left alone because the driver is not installed on Windows 11)
$netlogon = 'SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
$msv = "$lsa\MSV1_0"
$ts = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$winrm = 'SOFTWARE\Policies\Microsoft\Windows\WinRM'
$defender = 'SOFTWARE\Policies\Microsoft\Windows Defender'
Set-Dword $lsa LimitBlankPasswordUse 1
Set-Dword $lsa SCENoApplyLegacyAuditPolicy 1
Set-Dword $netlogon RequireSignOrSeal 1
Set-Dword $netlogon RequireStrongKey 1
Set-Dword 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' EnablePlainTextPassword 0
Set-Dword $lsa DisableDomainCreds 1
Set-Dword $lsa EveryoneIncludesAnonymous 0
Set-Dword 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' RestrictNullSessAccess 1
Set-Dword $msv AllowNullSessionFallback 0
Set-Dword "$lsa\pku2u" AllowOnlineID 0
Set-Dword "$sys\Kerberos\Parameters" SupportedEncryptionTypes 2147483640
Set-Dword $msv NTLMMinClientSec 537395200
Set-Dword $msv NTLMMinServerSec 537395200
Set-Dword $sys FilterAdministratorToken 1
Set-Dword $sys ConsentPromptBehaviorUser 0
Set-Dword $sys EnableSecureUIAPaths 1
Set-Dword $sys PromptOnSecureDesktop 1
Set-Dword 'SOFTWARE\Policies\Microsoft\Windows\Explorer' NoAutoplayfornonVolume 1
Set-Dword 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoAutorun 1
Set-Dword 'SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated 0
Set-Dword 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1
Set-Dword "$winrm\Client" AllowBasic 0
Set-Dword "$winrm\Service" AllowBasic 0
Set-Dword "$winrm\Service" AllowUnencryptedTraffic 0
Set-Dword $ts DisablePasswordSaving 1
Set-Dword $ts UserAuthentication 1
Set-Dword $ts fAllowToGetHelp 0
Set-Dword 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0
Set-Dword 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableIPSourceRouting 2
Set-Dword $lsa RunAsPPL 1
Set-Dword $defender DisableAntiSpyware 0
Set-Dword "$defender\Real-Time Protection" DisableRealtimeMonitoring 0
Set-Dword 'SOFTWARE\Policies\Microsoft\Windows\System' EnableSmartScreen 1
Set-Dword 'SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' MaxSize 196608

# services (SVC-001 to SVC-007): start type 4 = disabled, applied at the next restart.
# The services added in 0.3.0 (SVC-008 to SVC-017) are not installed on Windows 11, which
# already counts as compliant, so the GPO does not create registry keys for them.
foreach ($svc in 'RemoteAccess', 'SSDPSRV', 'upnphost', 'icssvc', 'sshd', 'RpcLocator', 'XblGameSave') {
  Set-Dword "SYSTEM\CurrentControlSet\Services\$svc" Start 4
}

# firewall (FW-001 to FW-003)
foreach ($p in 'DomainProfile', 'PrivateProfile', 'PublicProfile') {
  Set-Dword "SOFTWARE\Policies\Microsoft\WindowsFirewall\$p" EnableFirewall 1
}

Write-Host "GPO '$GpoName' linked to the Hardened OU. On WS01 run: gpupdate /force, then restart." -ForegroundColor Green
