# WinBaseline test lab (Hyper-V)

An isolated Active Directory lab for drift testing: one domain controller, two
Windows 11 clients, and a Windows Server 2025 member server. **WS01** gets the
baseline through Group Policy ("hardened"); **WS02** and **SRV01** keep Windows
defaults. Deliberate changes on any of them should show up as drift.

| VM | OS | IP | RAM / Disk | Role |
|---|---|---|---|---|
| DC01 | Windows Server 2022 Standard (Server Core) | 10.10.10.10 | 4 GB / 60 GB | Domain controller + DNS for `lab.atlas-tech.test` |
| WS01 | Windows 11 Enterprise (evaluation) | 10.10.10.21 | 4 GB / 64 GB | Hardened client (OU=Hardened) |
| WS02 | Windows 11 Enterprise (evaluation) | 10.10.10.22 | 4 GB / 64 GB | Default client (OU=Default) |
| SRV01 | Windows Server 2025 (evaluation) | 10.10.10.31 | 4 GB / 60 GB | Member server (OU=Default) |

- Storage: `Z:\Hyper-V\WinBaseline-Lab` (change in `lab-config.ps1`)
- Network: internal switch `WinBaseline-Lab` (10.10.10.0/24), host at 10.10.10.254 with NAT for internet
- Evaluation licenses: Windows 11 Enterprise 90 days, Server 2025 180 days
- Use the regular Windows 11 Enterprise evaluation, not LTSC (LTSC lacks components the
  baseline checks). Windows 11 **Home cannot join a domain**.

Scripts in `lab\` run on the host; scripts in `lab\guest\` run inside the VMs.
Run everything from **PowerShell as administrator**. Passwords are typed at prompts
and never stored in these files.

## Setup

1. **Turn on Hyper-V** (host), then restart Windows:
   `.\0-Enable-HyperV.ps1`
2. **Prepare the host**: VM storage on Z:, lab switch, NAT:
   `.\1-New-LabHost.ps1`
3. **Get the ISOs** into `Z:\Hyper-V\ISO` (DC01 uses a licensed Windows Server 2022 ISO):
   - Windows Server 2025: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2025
   - Windows 11 Enterprise: https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
4. **Create the VMs** (existing VMs are skipped, so this can be rerun to add SRV01):
   `.\2-New-LabVMs.ps1 -ServerIso Z:\Hyper-V\ISO\<server2022>.iso -ClientIso Z:\Hyper-V\ISO\<win11>.iso -MemberServerIso Z:\Hyper-V\ISO\<server2025>.iso`
5. **Install Windows** in each VM (Hyper-V Manager > Connect > Start; press a key to boot from DVD).
   - DC01: Server Core (no desktop) or Desktop Experience both work. On Core, choose
     option **15** in the blue menu to get PowerShell.
   - WS01/WS02: name the local account **itadmin**. If setup demands a Microsoft account,
     choose *Sign-in options > Domain join instead*.
6. **Copy the scripts and the tool in** (host, VM running):
   `.\3-Copy-ToLabVM.ps1 -VMName DC01,WS01,WS02,SRV01` (everything lands in `C:\WinBaseline`)
7. **DC01**: run `C:\WinBaseline\Set-DC.ps1` three times (it restarts between runs), then
   `C:\WinBaseline\New-HardenedGPO.ps1`.
8. **WS01**: `C:\WinBaseline\Join-Lab.ps1 -Name WS01 -IP 10.10.10.21 -OU Hardened`, then after the
   restart sign in as `LAB\Administrator`, run `gpupdate /force`, `C:\WinBaseline\Set-LocalHardening.ps1`, and restart.
9. **WS02**: `C:\WinBaseline\Join-Lab.ps1 -Name WS02 -IP 10.10.10.22 -OU Default`.
   **SRV01**: `C:\WinBaseline\Join-Lab.ps1 -Name SRV01 -IP 10.10.10.31 -OU Default`.
10. **Take clean checkpoints** (host) so every drift test can start from a known state:
    `Checkpoint-VM -Name DC01,WS01,WS02,SRV01 -SnapshotName 'Clean baseline'`

## Drift testing

Inside a client, from an administrator PowerShell in `C:\WinBaseline`:

```powershell
.\driftscan.exe                 # scan and save hash-chained evidence in .\results
.\driftscan.exe -verify         # check the evidence chain
```

Expected: WS01 is mostly compliant; WS02 shows drift on the settings Windows leaves at
default. Make a deliberate change (for example, turn off the public firewall profile or
add a "vendor" account to Administrators), scan again, and confirm the change is flagged.
Restore with `Restore-VMCheckpoint -VMName WS01 -Name 'Clean baseline' -Confirm:$false`.
