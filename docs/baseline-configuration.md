# Baseline configuration

This document describes the security baselines that driftscan checks: what each one covers, why
each setting matters, how severity works, how approved deviations and approved states are
handled, and how the baselines change over time. It is generated from the baseline files in
[`baseline/`](../baseline), so the check IDs, expected values, and severities match the files
exactly.

| Baseline | File | Checks |
|---|---|---|
| Windows 11 Enterprise Baseline v0.3.0 | [`windows11-baseline.yaml`](../baseline/windows11-baseline.yaml) | 90 |
| Windows Server 2022 Domain Controller Baseline v0.3.0 | [`windows-server-2022-dc-baseline.yaml`](../baseline/windows-server-2022-dc-baseline.yaml) | 87 |
| Windows Server 2025 Member Server Baseline v0.3.0 | [`windows-server-2025-ms-baseline.yaml`](../baseline/windows-server-2025-ms-baseline.yaml) | 80 |

## Scope

In scope:

- Windows 11 Enterprise workstations.
- Windows Server 2022 domain controllers.
- Windows Server 2025 member servers. Windows Server 2022 member servers can use the same file, because the two benchmarks share these settings.

Out of scope:

- Non-Windows systems, network devices, and cloud services.
- Settings stored outside the registry, services, accounts, firewall, audit policy, and installed-software list, such as user rights assignments and domain password policy.
- Automatic correction. driftscan only reads settings. Group Policy or an administrator fixes drift.

## Source and licensing

The baselines follow the Center for Internet Security (CIS) Benchmarks for Microsoft Windows 11
Enterprise, Windows Server 2022, and Windows Server 2025, using Level 1 settings that a program
can verify. A few checks are local rules rather than CIS recommendations, and their `cis` field
says `Organization policy`.

The CIS Benchmarks are free for non-commercial use. The baseline files and this document describe
each setting in original wording and do not copy benchmark text. Each check has a `cis` field for
the benchmark recommendation number. Commercial use of the benchmarks needs a CIS SecureSuite
membership.

## Which baseline a computer gets

| Computer role | Baseline file |
|---|---|
| Workstation | `windows11-baseline.yaml` |
| Domain controller | `windows-server-2022-dc-baseline.yaml` |
| Member or standalone server | `windows-server-2025-ms-baseline.yaml` |

driftscan reads each computer's role and picks the matching file. A `baseline:` field on a
computer in `hosts.yaml` overrides the role, and `-baseline` forces one file for every computer.
Every saved scan records the name and version of the baseline it used.

## Severity

| Severity | Meaning |
|---|---|
| high | Drift that directly allows credential theft, unauthorized access, or lost evidence, such as weak authentication protocols, the firewall off, LSASS unprotected, an unapproved administrator, or logon auditing off. Investigate the same day. |
| medium | Drift that weakens one layer of defense or reduces visibility, such as SMB signing not required, Autoplay on, an unneeded service enabled, or a secondary audit category off. Fix in the next maintenance window. |
| low | Hardening items with limited direct risk, such as CTRL+ALT+DEL not required or logoff auditing. Fix when convenient. |

Severity sets the order of work. It does not change whether a check passes. Record an approved
exception for a deviation you accept instead of lowering its severity.

## Windows 11 baseline (90 checks)

"Expected" is the compliant value. For a registry setting, a value that is not set counts as drift
unless the Windows default is already compliant, which the baseline records as `default`.

### Registry settings (48)

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `REG-001` | User Account Control: Run all administrators in Admin Approval Mode<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` | = 1 | high | Administrators work with standard rights until they approve an elevation, so malware cannot silently use full rights. |
| `REG-002` | User Account Control: Behavior of the elevation prompt for administrators<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | = 2 | medium | Elevation needs explicit consent on the secure desktop, which other programs cannot click through. |
| `REG-003` | Interactive logon: Do not require CTRL+ALT+DEL (Disabled)<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD` | = 0 | low | Users type their password only into the genuine Windows sign-in screen, not a fake prompt. |
| `REG-004` | Interactive logon: Machine inactivity limit (900 seconds or fewer)<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs` | ≤ 900 | medium | An unattended computer locks itself within 15 minutes. |
| `REG-005` | Network access: Do not allow anonymous enumeration of SAM accounts<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM` | = 1 | high | Anonymous users cannot list account names to target with password guessing. |
| `REG-006` | Network access: Do not allow anonymous enumeration of SAM accounts and shares<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous` | = 1 | high | Anonymous users cannot list accounts or shared folders. |
| `REG-007` | Network security: LAN Manager authentication level (NTLMv2 only, refuse LM and NTLM)<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel` | = 5 | high | Refuses the weak LM and NTLMv1 sign-in protocols, which are easy to crack. |
| `REG-008` | Network security: Do not store LAN Manager hash value on next password change<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash` | = 1 | high | Windows does not store LM password hashes, which can be cracked in minutes. |
| `REG-009` | WDigest Authentication (disable storing plaintext credentials)<br>`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` | = 0 | high | Passwords are not kept in memory in plaintext, where credential-theft tools look for them. |
| `REG-010` | Microsoft network server: Digitally sign communications (always)<br>`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature` | = 1 | medium | File-sharing traffic to this computer is signed, blocking tampering and relay attacks. |
| `REG-011` | Microsoft network client: Digitally sign communications (always)<br>`HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature` | = 1 | medium | File-sharing traffic from this computer is signed, blocking tampering and relay attacks. |
| `REG-012` | Configure SMB v1 server (Disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1` | = 0 | high | The obsolete SMBv1 protocol, exploited by WannaCry, stays off. |
| `REG-013` | Turn off Autoplay (All drives)<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun` | = 255 | medium | USB drives and discs cannot run code automatically when inserted. |
| `REG-015` | Accounts: Limit local account use of blank passwords to console logon only<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse` | = 1 | high | Accounts with a blank password cannot be used over the network. |
| `REG-016` | Audit: Force audit policy subcategory settings to override category settings<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy` | = 1 | medium | Detailed (advanced) audit settings take effect instead of older, coarser ones. |
| `REG-017` | Domain member: Digitally encrypt or sign secure channel data (always)<br>`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal` | = 1 | medium | Domain authentication traffic is always signed or encrypted. |
| `REG-018` | Domain member: Require strong (Windows 2000 or later) session key<br>`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey` | = 1 | medium | The domain secure channel uses strong session keys. |
| `REG-019` | Microsoft network client: Send unencrypted password to third-party SMB servers (Disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword` | = 0 | high | Passwords are never sent unencrypted to other file servers. |
| `REG-020` | Network access: Do not allow storage of passwords and credentials for network authentication<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DisableDomainCreds` | = 1 | medium | Network credentials are not cached where attackers could collect them. |
| `REG-021` | Network access: Let Everyone permissions apply to anonymous users (Disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous` | = 0 | high | Anonymous users do not inherit the permissions given to Everyone. |
| `REG-022` | Network access: Restrict anonymous access to Named Pipes and Shares<br>`HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RestrictNullSessAccess` | = 1 | high | Anonymous connections cannot reach named pipes and shared folders. |
| `REG-023` | Network security: Allow LocalSystem NULL session fallback (Disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\AllowNullSessionFallback` | = 0 | medium | System services do not fall back to anonymous NTLM sessions. |
| `REG-024` | Network security: Allow PKU2U authentication requests to use online identities (Disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID` | = 0 | medium | Consumer online accounts cannot be used to authenticate to this computer. |
| `REG-025` | Network security: Kerberos encryption types limited to AES128, AES256, and future types<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes` | = 2,147,483,640 | high | Kerberos uses AES only, removing weak RC4 and DES encryption targeted by Kerberoasting. |
| `REG-026` | Network security: Minimum session security for NTLM SSP clients (NTLMv2 and 128-bit encryption)<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec` | = 537,395,200 | medium | NTLM sessions started here require NTLMv2 and 128-bit encryption. |
| `REG-027` | Network security: Minimum session security for NTLM SSP servers (NTLMv2 and 128-bit encryption)<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec` | = 537,395,200 | medium | NTLM sessions accepted here require NTLMv2 and 128-bit encryption. |
| `REG-028` | User Account Control: Admin Approval Mode for the built-in Administrator account<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken` | = 1 | high | The built-in Administrator account gets the same UAC protection as other administrators. |
| `REG-029` | User Account Control: Behavior of the elevation prompt for standard users (Automatically deny)<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser` | = 0 | medium | Standard users are never prompted for administrator credentials, so they cannot be tricked into entering them. |
| `REG-030` | User Account Control: Only elevate UIAccess applications installed in secure locations<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths` | = 1 | medium | Programs that can bypass UI isolation must be installed in protected folders. |
| `REG-031` | User Account Control: Switch to the secure desktop when prompting for elevation<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop` | = 1 | medium | Elevation prompts appear on the secure desktop, where they cannot be spoofed. |
| `REG-032` | Disallow Autoplay for non-volume devices<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume` | = 1 | medium | Phones, cameras, and other devices cannot trigger Autoplay. |
| `REG-033` | Set the default behavior for AutoRun (Do not execute any autorun commands)<br>`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun` | = 1 | medium | Autorun commands on removable media are ignored. |
| `REG-034` | Windows Installer: Always install with elevated privileges (Disabled)<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` | = 0 | high | Users cannot install packages with SYSTEM rights, a common privilege-escalation path. |
| `REG-035` | Windows PowerShell: Turn on PowerShell Script Block Logging<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` | = 1 | medium | PowerShell records the code it runs, which investigators need after an attack. |
| `REG-036` | WinRM Client: Allow Basic authentication (Disabled)<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic` | = 0 | high | Remote management from this computer never uses Basic authentication. |
| `REG-037` | WinRM Service: Allow Basic authentication (Disabled)<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic` | = 0 | high | Remote management to this computer never accepts Basic authentication. |
| `REG-038` | WinRM Service: Allow unencrypted traffic (Disabled)<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic` | = 0 | high | Remote management traffic to this computer is always encrypted. |
| `REG-039` | Remote Desktop: Do not allow passwords to be saved<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving` | = 1 | medium | Remote Desktop cannot save passwords that could be reused by others. |
| `REG-040` | Remote Desktop: Require user authentication for remote connections by using Network Level Authentication<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication` | = 1 | high | Users authenticate before a Remote Desktop session starts, reducing exposure to attacks. |
| `REG-041` | Remote Assistance: Configure Solicited Remote Assistance (Disabled)<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp` | = 0 | medium | Users cannot invite uncontrolled remote control of their computer. |
| `REG-042` | DNS Client: Turn off multicast name resolution (LLMNR)<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` | = 0 | medium | Turns off LLMNR, which attackers spoof to capture password hashes. |
| `REG-043` | MSS: IP source routing protection level, IPv4 (Highest protection, source routing completely disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting` | = 2 | medium | Packets cannot dictate their own route through this computer. |
| `REG-044` | Configure LSASS to run as a protected process<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | ≥ 1 | high | LSASS runs as a protected process, blocking tools that dump credentials from memory. |
| `REG-045` | Microsoft Defender Antivirus is not turned off by policy<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` | = 0 | high | Microsoft Defender Antivirus cannot be switched off through policy. |
| `REG-046` | Microsoft Defender real-time protection is not turned off by policy<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` | = 0 | high | Defender real-time protection cannot be switched off through policy. |
| `REG-047` | Configure Windows Defender SmartScreen (Enabled)<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen` | = 1 | medium | SmartScreen warns before running unknown downloaded programs. |
| `REG-048` | Security event log: Maximum log size (196,608 KB or greater)<br>`HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize` | ≥ 196,608 | medium | The Security log keeps enough history to investigate an incident. |
| `REG-049` | Configure SMB v1 client driver (Disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start` | = 4 | high | The SMBv1 client driver stays disabled. |

### Services (17)

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `SVC-001` | Routing and Remote Access (RemoteAccess) is disabled<br>`Service: RemoteAccess` | Disabled or not installed | medium | Routing and remote access is not needed on these computers and adds attack surface. |
| `SVC-002` | SSDP Discovery (SSDPSRV) is disabled<br>`Service: SSDPSRV` | Disabled or not installed | low | Network device discovery is a consumer feature that widens the attack surface. |
| `SVC-003` | UPnP Device Host (upnphost) is disabled<br>`Service: upnphost` | Disabled or not installed | low | UPnP device hosting lets devices open ports and is not needed in business use. |
| `SVC-004` | Windows Mobile Hotspot Service (icssvc) is disabled<br>`Service: icssvc` | Disabled or not installed | medium | A mobile hotspot could bridge the corporate network to an outside device. |
| `SVC-005` | OpenSSH SSH Server (sshd) is disabled or not installed<br>`Service: sshd` | Disabled or not installed | medium | An unmanaged SSH server would provide an extra remote shell. |
| `SVC-006` | Remote Procedure Call (RPC) Locator (RpcLocator) is disabled<br>`Service: RpcLocator` | Disabled or not installed | low | A legacy RPC service that modern Windows does not need. |
| `SVC-007` | Xbox Live Game Save (XblGameSave) is disabled<br>`Service: XblGameSave` | Disabled or not installed | low | A consumer gaming service with no business purpose. |
| `SVC-008` | Computer Browser (Browser) is disabled or not installed<br>`Service: Browser` | Disabled or not installed | low | A legacy network-browsing service tied to SMBv1. |
| `SVC-009` | IIS Admin Service (IISADMIN) is disabled or not installed<br>`Service: IISADMIN` | Disabled or not installed | low | A web server administration service does not belong on a workstation. |
| `SVC-010` | Infrared monitor service (irmon) is disabled or not installed<br>`Service: irmon` | Disabled or not installed | low | Infrared file transfer is obsolete and unmonitored. |
| `SVC-011` | Windows Subsystem for Linux manager (LxssManager) is disabled or not installed<br>`Service: LxssManager` | Disabled or not installed | low | A Linux environment can run tools outside Windows security controls. |
| `SVC-012` | Microsoft FTP Service (FTPSVC) is disabled or not installed<br>`Service: FTPSVC` | Disabled or not installed | low | An FTP server sends data and passwords without encryption. |
| `SVC-013` | Simple TCP/IP Services (simptcp) is disabled or not installed<br>`Service: simptcp` | Disabled or not installed | low | Legacy network services (echo, chargen) are only useful to attackers. |
| `SVC-014` | Special Administration Console Helper (sacsvr) is disabled or not installed<br>`Service: sacsvr` | Disabled or not installed | low | An emergency management console is not needed on these computers. |
| `SVC-015` | Web Management Service (WMSvc) is disabled or not installed<br>`Service: WMSvc` | Disabled or not installed | low | Remote web server management does not belong on a workstation. |
| `SVC-016` | World Wide Web Publishing Service (W3SVC) is disabled or not installed<br>`Service: W3SVC` | Disabled or not installed | low | A web server does not belong on a workstation. |
| `SVC-017` | Xbox Live Networking Service (XboxNetApiSvc) is disabled<br>`Service: XboxNetApiSvc` | Disabled or not installed | low | A consumer gaming network service with no business purpose. |

### Built-in accounts (2)

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `ACCT-001` | Accounts: Guest account status (Disabled) | Disabled | high | The shared Guest account cannot be used to sign in. |
| `ACCT-002` | Accounts: Rename administrator account | Renamed | medium | Attackers cannot assume the built-in administrator is named "Administrator". |

### Administrators group (1)

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `GRP-001` |
| Only approved accounts are members of the local Administrators group |
| Only: Administratorlocadm          # renamed built-in Administrator in the lab (see lab\guest\Set-LocalHardening.ps1)itadminDomain Admins |
| high |
| Detects extra administrators, such as a vendor account that was never removed. |

### Windows Firewall (3)

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `FW-001` | Windows Firewall: Domain profile firewall state (On) | On | high | The firewall is on while connected to the company domain. |
| `FW-002` | Windows Firewall: Private profile firewall state (On) | On | high | The firewall is on for private networks. |
| `FW-003` | Windows Firewall: Public profile firewall state (On) | On | high | The firewall is on for public networks such as hotels and cafes. |

### Audit policy (17)

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `AUD-001` | Audit Credential Validation (Success and Failure)<br>`Audit subcategory {0CCE923F-69AE-11D9-BED3-505054503030}` | Success And Failure | medium | Records every attempt to check a password, revealing password guessing. |
| `AUD-002` | Audit Security Group Management (Success)<br>`Audit subcategory {0CCE9237-69AE-11D9-BED3-505054503030}` | Success | medium | Records changes to security groups, such as being added to Administrators. |
| `AUD-003` | Audit User Account Management (Success and Failure)<br>`Audit subcategory {0CCE9235-69AE-11D9-BED3-505054503030}` | Success And Failure | medium | Records account creation, changes, and deletion. |
| `AUD-004` | Audit Account Lockout (Failure)<br>`Audit subcategory {0CCE9217-69AE-11D9-BED3-505054503030}` | Failure | medium | Records account lockouts, a sign of password attacks. |
| `AUD-005` | Audit Logon (Success and Failure)<br>`Audit subcategory {0CCE9215-69AE-11D9-BED3-505054503030}` | Success And Failure | high | Records sign-ins and failed sign-ins. |
| `AUD-006` | Audit Special Logon (Success)<br>`Audit subcategory {0CCE921B-69AE-11D9-BED3-505054503030}` | Success | medium | Records sign-ins with administrator-level rights. |
| `AUD-007` | Audit Audit Policy Change (Success)<br>`Audit subcategory {0CCE922F-69AE-11D9-BED3-505054503030}` | Success | high | Records changes to the audit policy itself, which attackers make to hide. |
| `AUD-008` | Audit Logoff (Success)<br>`Audit subcategory {0CCE9216-69AE-11D9-BED3-505054503030}` | Success | low | Records sign-outs, completing each session record. |
| `AUD-009` | Audit Other Logon/Logoff Events (Success and Failure)<br>`Audit subcategory {0CCE921C-69AE-11D9-BED3-505054503030}` | Success And Failure | medium | Records other session events such as locks, unlocks, and reconnections. |
| `AUD-010` | Audit Group Membership (Success)<br>`Audit subcategory {0CCE9249-69AE-11D9-BED3-505054503030}` | Success | medium | Records the group memberships of each sign-in. |
| `AUD-011` | Audit Process Creation (Success)<br>`Audit subcategory {0CCE922B-69AE-11D9-BED3-505054503030}` | Success | medium | Records every program started, essential for tracing an attack. |
| `AUD-012` | Audit Authentication Policy Change (Success)<br>`Audit subcategory {0CCE9230-69AE-11D9-BED3-505054503030}` | Success | medium | Records changes to authentication policy. |
| `AUD-013` | Audit Sensitive Privilege Use (Success and Failure)<br>`Audit subcategory {0CCE9228-69AE-11D9-BED3-505054503030}` | Success And Failure | medium | Records use of powerful privileges. |
| `AUD-014` | Audit Security State Change (Success)<br>`Audit subcategory {0CCE9210-69AE-11D9-BED3-505054503030}` | Success | medium | Records security system start-up and shutdown. |
| `AUD-015` | Audit Security System Extension (Success)<br>`Audit subcategory {0CCE9211-69AE-11D9-BED3-505054503030}` | Success | medium | Records new security packages and services being installed. |
| `AUD-016` | Audit System Integrity (Success and Failure)<br>`Audit subcategory {0CCE9212-69AE-11D9-BED3-505054503030}` | Success And Failure | high | Records integrity problems with the security subsystem. |
| `AUD-017` | Audit Removable Storage (Success and Failure)<br>`Audit subcategory {0CCE9245-69AE-11D9-BED3-505054503030}` | Success And Failure | medium | Records files read from or written to USB drives. |

### Installed software (2)

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `SW-001` | No peer-to-peer file sharing software installed | Not installed | medium | File-sharing programs can leak data and bring in malware. |
| `SW-002` | No unapproved remote access tools installed | Not installed | high | Unapproved remote access tools are a common way for attackers to keep access. |

## Server baselines

### Windows Server 2022 domain controller (87 checks)

This baseline starts from the Windows 11 baseline and keeps the same check IDs for shared settings.
It adds controls for domain controllers and leaves out settings that do not apply. On a domain
controller, `GRP-001` approves the domain's Administrator, Domain Admins, and Enterprise Admins.

Added for this role (10):

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `REG-050` | Domain controller: LDAP server signing requirements (Require signing)<br>`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity` | = 2 | high | Directory (LDAP) traffic to the domain controller must be signed, blocking tampering. |
| `REG-051` | Domain controller: LDAP server channel binding token requirements (Always)<br>`HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding` | = 2 | high | LDAP sign-ins are bound to their encrypted channel, blocking relay attacks. |
| `REG-052` | Domain controller: Refuse machine account password changes (Disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange` | = 0 | medium | Computer accounts keep changing their passwords on schedule. |
| `REG-053` | Domain controller: Allow server operators to schedule tasks (Disabled)<br>`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SubmitControl` | = 0 | medium | Server Operators cannot schedule tasks, closing a path to domain controller control. |
| `SVC-018` | Print Spooler (Spooler) is disabled on domain controllers<br>`Service: Spooler` | Disabled or not installed | high | Print Spooler on a domain controller is the target of PrintNightmare-style attacks. |
| `AUD-018` | Audit Kerberos Authentication Service (Success and Failure)<br>`Audit subcategory {0CCE9242-69AE-11D9-BED3-505054503030}` | Success And Failure | medium | Records Kerberos ticket requests on the domain controller. |
| `AUD-019` | Audit Kerberos Service Ticket Operations (Success and Failure)<br>`Audit subcategory {0CCE9240-69AE-11D9-BED3-505054503030}` | Success And Failure | medium | Records Kerberos service ticket activity, revealing Kerberoasting. |
| `AUD-020` | Audit Computer Account Management (Success)<br>`Audit subcategory {0CCE9236-69AE-11D9-BED3-505054503030}` | Success | medium | Records computer accounts being created, changed, or deleted. |
| `AUD-021` | Audit Directory Service Access (Failure)<br>`Audit subcategory {0CCE923B-69AE-11D9-BED3-505054503030}` | Failure | medium | Records failed attempts to read directory objects. |
| `AUD-022` | Audit Directory Service Changes (Success)<br>`Audit subcategory {0CCE923C-69AE-11D9-BED3-505054503030}` | Success | medium | Records changes to directory objects. |

Left out for this role (13):

| ID | Setting | Reason |
|---|---|---|
| `REG-005` | Network access: Do not allow anonymous enumeration of SAM accounts | The benchmark applies this setting to member servers only. |
| `REG-006` | Network access: Do not allow anonymous enumeration of SAM accounts and shares | The benchmark applies this setting to member servers only. |
| `SVC-002` | SSDP Discovery (SSDPSRV) is disabled | Consumer or client-only feature that Windows Server does not use. |
| `SVC-003` | UPnP Device Host (upnphost) is disabled | Consumer or client-only feature that Windows Server does not use. |
| `SVC-004` | Windows Mobile Hotspot Service (icssvc) is disabled | Consumer or client-only feature that Windows Server does not use. |
| `SVC-007` | Xbox Live Game Save (XblGameSave) is disabled | Consumer or client-only feature that Windows Server does not use. |
| `SVC-008` | Computer Browser (Browser) is disabled or not installed | Client-only feature not present on Windows Server. |
| `SVC-009` | IIS Admin Service (IISADMIN) is disabled or not installed | Servers may legitimately host web or FTP services; approve them per server instead. |
| `SVC-011` | Windows Subsystem for Linux manager (LxssManager) is disabled or not installed | Client-only feature not present on Windows Server. |
| `SVC-012` | Microsoft FTP Service (FTPSVC) is disabled or not installed | Servers may legitimately host web or FTP services; approve them per server instead. |
| `SVC-015` | Web Management Service (WMSvc) is disabled or not installed | Servers may legitimately host web or FTP services; approve them per server instead. |
| `SVC-016` | World Wide Web Publishing Service (W3SVC) is disabled or not installed | Servers may legitimately host web or FTP services; approve them per server instead. |
| `SVC-017` | Xbox Live Networking Service (XboxNetApiSvc) is disabled | Consumer or client-only feature that Windows Server does not use. |

### Windows Server 2025 member server (80 checks)

This baseline starts from the Windows 11 baseline and keeps the same check IDs for shared settings.
It adds computer account auditing and leaves out client-only services.

Added for this role (1):

| ID | Setting | Expected | Severity | Why it matters |
|---|---|---|---|---|
| `AUD-020` |
| Audit Computer Account Management (Success)<br>`Audit subcategory {0CCE9236-69AE-11D9-BED3-505054503030}` |
| Success |
| medium |
| Records computer accounts being created, changed, or deleted. |

Left out for this role (11):

| ID | Setting | Reason |
|---|---|---|
| `SVC-002` | SSDP Discovery (SSDPSRV) is disabled | Consumer or client-only feature that Windows Server does not use. |
| `SVC-003` | UPnP Device Host (upnphost) is disabled | Consumer or client-only feature that Windows Server does not use. |
| `SVC-004` | Windows Mobile Hotspot Service (icssvc) is disabled | Consumer or client-only feature that Windows Server does not use. |
| `SVC-007` | Xbox Live Game Save (XblGameSave) is disabled | Consumer or client-only feature that Windows Server does not use. |
| `SVC-008` | Computer Browser (Browser) is disabled or not installed | Client-only feature not present on Windows Server. |
| `SVC-009` | IIS Admin Service (IISADMIN) is disabled or not installed | Servers may legitimately host web or FTP services; approve them per server instead. |
| `SVC-011` | Windows Subsystem for Linux manager (LxssManager) is disabled or not installed | Client-only feature not present on Windows Server. |
| `SVC-012` | Microsoft FTP Service (FTPSVC) is disabled or not installed | Servers may legitimately host web or FTP services; approve them per server instead. |
| `SVC-015` | Web Management Service (WMSvc) is disabled or not installed | Servers may legitimately host web or FTP services; approve them per server instead. |
| `SVC-016` | World Wide Web Publishing Service (W3SVC) is disabled or not installed | Servers may legitimately host web or FTP services; approve them per server instead. |
| `SVC-017` | Xbox Live Networking Service (XboxNetApiSvc) is disabled | Consumer or client-only feature that Windows Server does not use. |

## Approved exceptions

An exception records a deviation that the organization accepts, for example a service that a
vendor application needs until it is replaced.

- Each exception records the check ID, the computers it covers or all computers, the reason, the person who approved it, and an expiry date.
- driftscan rejects placeholder values such as `TODO`, so nobody can save an exception without a real reason and approver.
- While an exception is in force, driftscan reports the check as `EXCEPTION` instead of `DRIFT`. The deviation stays in the evidence but does not raise the drift alert.
- From the day after the expiry date, the check is `DRIFT` again and the note says the exception expired. The dashboard lists exceptions that expire within 30 days.
- `-capture -propose-exceptions` drafts an entry for every drifting check with `TODO` placeholders, which a person must replace before the baseline loads.

## Approved state (capture)

The baseline says whether a computer meets policy. A capture records what one computer looked like
when an administrator approved it, so later scans can report what changed.

- The administrator approves a scan they reviewed, from the dashboard or with `-capture`, so the approved state is exactly what they saw.
- An approval needs a note and a confirmation, and it records who approved it and when. Unreadable checks must be excluded by name.
- Every later scan marks each check `UNCHANGED` or `CHANGED` against the approved state.
- driftscan hash-chains approvals the same way it chains scans. A new approval joins the history without replacing earlier ones, and driftscan refuses an approval file that someone edited.

## Versioning and change control

| Change | Version rule and process |
|---|---|
| Fix a title, CIS number, or comment | Patch version (0.3.0 to 0.3.1). Peer review. |
| Add checks or change an expected value | Minor version (0.2.0 to 0.3.0). Review, run the lab drift test, and get approval before release. |
| Remove checks or change what an ID means | Major version (0.x to 1.0). As for minor, plus notice to administrators, because old and new results are no longer comparable. |

- A check ID is never reused for a different setting. `REG-014` was retired in 0.2.0 when `FW-001` replaced it.
- A setting has the same ID in every baseline, so results from workstations and servers can be compared.
- The baseline files live in Git. Every change is a reviewed commit, and every scan records the baseline version it used.
- Version 0.1.0 had 14 registry checks. Version 0.2.0 had 35 checks across seven check types. Version 0.3.0 has 90 Windows 11 checks and adds the domain controller and member server baselines.

## Mapping to NIST SP 800-171

Organizations that handle Controlled Unclassified Information must meet NIST SP 800-171. The checks
support these requirements:

| Check category | NIST SP 800-171 requirements |
|---|---|
| The baseline and drift detection | 3.4.1 Baseline configurations; 3.4.2 Security configuration settings; 3.4.3 Track and review changes |
| UAC, Administrators group, built-in accounts | 3.1.5 Least privilege; 3.1.7 Prevent non-privileged users from running privileged functions; 3.5.2 Authenticate users and devices |
| Inactivity lock, CTRL+ALT+DEL | 3.1.10 Session lock |
| LM and NTLM, WDigest, Kerberos, LSASS protection | 3.5.10 Store and transmit only cryptographically protected passwords |
| SMB and LDAP signing, WinRM encryption, RDP NLA | 3.13.8 Cryptography for information in transit; 3.1.12 Monitor and control remote access |
| Windows Firewall | 3.13.1 Monitor and control communications at system boundaries |
| Services, Autoplay, prohibited software | 3.4.6 Least functionality; 3.4.7 Restrict nonessential programs, ports, and services; 3.4.8 Deny-by-exception for unauthorized software |
| Audit policy, PowerShell logging, log size | 3.3.1 Create and retain audit records; 3.3.2 Trace actions to individual users |
| Microsoft Defender, SmartScreen | 3.14.2 Protect against malicious code |

## Known limitations

- Windows only reports audit policy on the computer itself. Remote scans show these checks as unreadable, so use scheduled scans, which run locally.
- Remote scans need the Remote Registry service, which the CIS Level 2 profile recommends disabling. Scheduled scans do not.
- Registry checks compare whole numbers. Settings stored as text or lists, and user rights assignments, are not covered yet.
- driftscan compares audit results using the English words Success and Failure. On non-English Windows it still finds each subcategory by its fixed ID, but the result text may need translation support.
- The `cis` recommendation numbers still need to be filled in.