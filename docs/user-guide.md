# driftscan user guide

This guide is for IT and system administrators who scan Windows computers, review the results,
and approve configurations with driftscan. It covers driftscan 1.0 and baselines version 0.3.0.

- [1. What driftscan does](#1-what-driftscan-does)
- [2. Requirements](#2-requirements)
- [3. Install](#3-install)
- [4. Scan this computer](#4-scan-this-computer)
- [5. Read the results](#5-read-the-results)
- [6. Approve a computer's configuration](#6-approve-a-computers-configuration)
- [7. Record approved exceptions](#7-record-approved-exceptions)
- [8. Scan many computers](#8-scan-many-computers)
- [9. Use the dashboard](#9-use-the-dashboard)
- [10. Check the evidence](#10-check-the-evidence)
- [11. Troubleshooting](#11-troubleshooting)
- [12. Command reference](#12-command-reference)

## 1. What driftscan does

driftscan compares a Windows computer with a documented security baseline and reports every
setting that differs from the approved value. It saves each result as evidence that later edits
cannot hide, and a local dashboard shows every computer in one place.

driftscan only reads settings. It never changes a setting, installs nothing on the computers it
reads, and stores no passwords. Fixing a setting it reports is the administrator's job, usually
through Group Policy.

The [baseline configuration](baseline-configuration.md) document lists every check and explains
why it matters.

## 2. Requirements

| Item | Requirement |
|---|---|
| Operating system | Windows 11, Windows Server 2022, or Windows Server 2025 |
| Account | A local administrator on the computer you scan. Audit policy checks and captures need an administrator terminal. |
| Remote scans | A domain account that is an administrator on each target, the Remote Registry service running on each target, and the firewall groups "File and Printer Sharing" and "Remote Service Management" enabled |
| Browser | Any current browser on the computer that runs the dashboard |
| Building from source | Go 1.27 or later. `go.mod` pins the patched `go1.27.2` toolchain, which Go downloads automatically. |

## 3. Install

driftscan is one program with no installer. Copy these files to `C:\WinBaseline` on each computer
that runs scans:

| File | Purpose |
|---|---|
| `driftscan.exe` | The scanner and dashboard |
| `baseline\windows11-baseline.yaml` | Rules for Windows 11 workstations (90 checks) |
| `baseline\windows-server-2022-dc-baseline.yaml` | Rules for domain controllers (87 checks) |
| `baseline\windows-server-2025-ms-baseline.yaml` | Rules for member servers (80 checks) |
| `hosts.yaml` (optional) | The list of computers you are approved to scan over the network |

To check a downloaded release, compare its SHA-256 hash with `SHA256SUMS.txt` on the release page:

```powershell
(Get-FileHash C:\WinBaseline\driftscan.exe -Algorithm SHA256).Hash
```

To build it yourself:

```powershell
go test ./...
go build -o driftscan.exe ./cmd/driftscan
```

Scan results describe a computer's weak points. Keep the results folder readable by
administrators only.

## 4. Scan this computer

1. Right-click Start and open **Terminal (Admin)**.
2. Run the scan:

   ```powershell
   cd C:\WinBaseline
   .\driftscan.exe -out results
   ```

driftscan picks the baseline that matches the computer's role: workstation, member server, or
domain controller. To use a specific file instead, add `-baseline baseline\<file name>.yaml`.

The scan takes less than a second. It prints a table of every check, saves a JSON evidence file
and an HTML report in the results folder, and ends with a summary such as
`90 checks: 41 compliant, 49 drift, 0 approved exceptions, 0 errors`.

The exit code tells scripts and Task Scheduler what the scan found:

| Code | Meaning |
|---|---|
| 0 | Nothing to report. Every check is compliant or covered by an approved exception. |
| 1 | Drift found. |
| 2 | The scan could not finish, or a computer returned nothing. |
| 3 | Evidence verification failed. Saved evidence was edited, removed, or reordered. |
| 4 | No drift, but something changed since the approved capture. |

When several apply, driftscan returns the most serious one, in the order 2, 3, 1, 4.

## 5. Read the results

Each check has a status. The status always appears as a word, so the reports still read correctly
in black and white.

| Status | Meaning |
|---|---|
| `COMPLIANT` | The setting matches the baseline. |
| `DRIFT` | The setting differs from the baseline. Fix it, or record an approved exception. |
| `EXCEPTION` | The setting differs, but an approved exception covers it. The report shows the reason and the approver. |
| `ERROR` | driftscan could not read the setting. The note gives the reason, for example missing administrator rights. |

After a computer has an approved capture (section 6), each check also shows a change:

| Change | Meaning |
|---|---|
| `UNCHANGED` | The value matches the approved capture. |
| `CHANGED` | The value differs from the approved capture. The note shows the old and new values. |
| `NEW_CHECK` | The baseline gained this check after the capture was taken. |

Severity sets the order of work. Investigate high-severity drift the same day, fix medium-severity
drift in the next maintenance window, and fix low-severity drift when convenient.

The HTML report beside each JSON file shows the same results in a browser. It lists changed
settings first, then drift, errors, exceptions, and compliant checks. Its footer names the JSON
evidence file and its SHA-256 hash.

## 6. Approve a computer's configuration

A baseline says what every computer should look like. An approved capture records what one
computer looked like when an administrator signed off on it. Later scans compare against both, so
a new change stands out even on a computer with known, accepted gaps.

### From the dashboard

1. Open the computer's page and review its latest scan.
2. Select **Approve as baseline**.
3. On the review page, type an approval note, for example "Post-build sign-off, ticket IT-102", and confirm that you reviewed the results.
4. If the scan has unreadable checks, tick the box that excludes them by name, or fix the cause and scan again.
5. Optionally tick **Also draft exceptions**. driftscan then writes a draft exception for every drifting check, as described in section 7.
6. Select **Approve as baseline**. The computer page now shows the approval date, your account name, and the note.

### From the command line

```powershell
.\driftscan.exe -capture -out results
```

Run this from an administrator terminal. driftscan refuses to capture without administrator
rights, because it could not read the audit policy and would record it as unreadable.

Each approval is added to the history and never replaces an earlier one. If someone edits an
approval file, the next scan still runs, skips the comparison, shows a warning, and exits with
code 3.

## 7. Record approved exceptions

Use an exception when a computer must keep a setting that the baseline flags, for example a service
that a vendor application needs until it is replaced. Add the exception to the `exceptions:` list
at the end of the baseline file:

```yaml
exceptions:
  - check: SW-002
    hosts: [WS02]
    reason: "Helpdesk uses TeamViewer until the Intune rollout finishes"
    approved_by: "J. Lee, IT Manager"
    expires: "2026-12-31"
```

The check ID, reason, approver, and expiry date are required. Leave out `hosts` to cover every
computer. driftscan refuses to load a baseline with a missing field, an unknown check ID, or a
reason or approver that still says `TODO`.

From the day after the expiry date, the check is reported as `DRIFT` again. The dashboard's
Baseline page lists exceptions that expire within 30 days.

To draft exceptions for every drifting check, run:

```powershell
.\driftscan.exe -capture -propose-exceptions -out results
```

driftscan writes the drafts to `results\captures\proposed-exceptions-<computer>-<time>.yaml` with
`TODO` placeholders. Fill in each reason and approver, delete the entries you do not approve, and
paste the rest into the baseline file. driftscan never edits the baseline file for you.

## 8. Scan many computers

There are two ways to scan more than one computer. Use scheduled scans where you can.

| | Scheduled scans (recommended) | Remote scans |
|---|---|---|
| How it works | Each computer scans itself every day as SYSTEM and saves evidence to a shared folder | One computer reads the others over the network |
| Audit policy | Read on every computer | Not readable. Windows has no remote audit policy interface, so these checks show `ERROR`. |
| Remote Registry | Not needed, so it can stay disabled as CIS recommends | Must be running on every target |
| Setup | A task on each computer and one shared folder | A host list and remote access on each target |

### Scheduled scans

On the computer that runs the dashboard, create the evidence share. Each computer can write only
to its own folder, and only Domain Admins can read all of them.

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
C:\WinBaseline\New-EvidenceShare.ps1 -Computers DC01,WS02,SRV01
```

On each computer that should scan itself, register the task:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
C:\WinBaseline\Install-ScanTask.ps1 -Share \\WS01\WinBaselineEvidence
```

The task "WinBaseline Drift Scan" runs every day at 06:00 and five minutes after each restart. The
script picks the baseline from the computer's role, runs the task once, and prints the result.
Exit codes 0, 1, and 4 mean the scan worked. To remove the task, run
`Install-ScanTask.ps1 -Remove`. Both scripts are in [`lab/guest`](../lab/guest).

### Remote scans

Every computer you scan over the network must be listed in `hosts.yaml`, together with a record of
who approved the scanning. driftscan has no option to scan an IP address range or a wildcard, so
the list is the full approved scope. See [`hosts.example.yaml`](../hosts.example.yaml).

```yaml
authorization:
  approved_by: "J. Lee, IT Manager"
  approved: "2026-10-21"
  expires: "2027-01-19"
  scope: "quarterly CIS review of the lab computers"
hosts:
  - name: WS02
    label: "default client"
  - name: SRV01
    label: "member server"
    baseline: windows-server-2025-ms-baseline.yaml
```

driftscan refuses to scan while `approved_by` or `scope` says `TODO`, and stops once the expiry
date passes. The `baseline` field is optional. Without it, the computer's role picks the baseline.

On each target computer, start Remote Registry and open the firewall:

```powershell
Set-Service RemoteRegistry -StartupType Automatic; Start-Service RemoteRegistry
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
Enable-NetFirewallRule -DisplayGroup "Remote Service Management"
```

Then scan every listed computer, or one of them:

```powershell
.\driftscan.exe -hosts hosts.yaml -out results
.\driftscan.exe -hosts hosts.yaml -host WS02 -out results
```

driftscan reads each computer as the Windows account you run it as. Run it as a domain account
that is an administrator on the targets. Each computer's evidence goes to its own folder,
`results\<computer>`.

## 9. Use the dashboard

Start the dashboard from an administrator terminal, then open http://127.0.0.1:8080 in a browser
on the same computer:

```powershell
.\driftscan.exe -serve -hosts hosts.yaml -out results
```

Leave the terminal open while you use the dashboard, and press Ctrl+C to stop it. Leave out
`-hosts` if you only scan this computer. The dashboard only accepts connections from the same
computer, so other computers on the network cannot open it.

| Page | What it shows and what you can do |
|---|---|
| Fleet | Every computer, most urgent first, with four totals at the top: computers that need attention, settings changed since capture, drift findings, and evidence status. The Needs attention list names each problem. |
| Computer | One computer's state, its changes since the approved capture, a drift trend, and the **Approve as baseline** button. Tabs open the latest results and the scan history. |
| Results | One scan's checks, grouped by type. Groups with problems open automatically. Filter by status and severity with the buttons at the top. |
| Compare | Two scans of one computer side by side: new drift, fixed settings, settings still drifting, and changed values. |
| Scan | Start a scan of this computer or of the approved computers, and watch its progress. **Manage computers** adds, skips, or removes computers in `hosts.yaml` and tests remote access. |
| Baseline | Every baseline, which computers use it, its checks, and the approved exceptions with their expiry dates. |
| Evidence | Runs the evidence check over every computer's records and shows the result. |
### Add a computer

1. Open **Scan**, then **Manage computers**.
2. Type one computer name and an optional label. driftscan rejects IP ranges and wildcards.
3. Confirm that the computer is within the approved scope shown on the form.
4. Select **Test access first**. REACHABLE means a scan can read the computer.
5. Select **Add computer**. driftscan saves the change to `hosts.yaml` with your account name and the date, and logs it in `hosts-changes.log`.

Skip pauses scanning a computer without removing it. Removing a computer keeps its saved evidence.
The dashboard refuses all changes while the scanning approval in `hosts.yaml` is missing or
expired.

## 10. Check the evidence

Every saved scan and approval stores the SHA-256 hash of the record before it, and each folder's
`chain.log` lists every record with its hash. To check all of them, run:

```powershell
.\driftscan.exe -verify -out results
```

A clean result means no saved record was edited, deleted from the middle, or reordered. If a check
fails, driftscan names the first record that fails and exits with code 3. The Evidence page in the
dashboard runs the same check.

The check has one known gap. Someone with write access to the folder can delete the newest record
together with its last line in `chain.log`, and the shorter chain still verifies. Copying the
latest hash to a location that person cannot change closes this gap and is planned.

## 11. Troubleshooting

| What you see | Cause | What to do |
|---|---|---|
| "running scripts is disabled on this system" | The PowerShell execution policy blocks the lab scripts. | Run `Set-ExecutionPolicy -Scope Process Bypass -Force` in the same window first. |
| Audit checks show `ERROR` with "cannot be read remotely" | Windows cannot report audit policy over the network. | Use scheduled scans (section 8), or scan on the computer itself. |
| Audit checks show `ERROR` on a local scan | The terminal is not running as administrator. | Open Terminal (Admin) and scan again. |
| Test access shows REMOTE REGISTRY OFF | Remote Registry is stopped, the firewall blocks it, or your account has no rights on the target. | Start Remote Registry, enable the two firewall groups, and run as a domain administrator. |
| A remote scan shows NOTHING READ | The account running driftscan cannot sign in to the target. | Run `whoami`. It must show a domain account, not a local account. |
| `-capture` exits with code 2 | The terminal is not running as administrator. | Open Terminal (Admin) and capture again. |
| The baseline or `hosts.yaml` will not load | A required field is missing or still says `TODO`, a check ID is unknown, or the approval expired. | Read the message, fix the named field, and run again. |
| Copying `driftscan.exe` fails with "file in use" | The dashboard is still running. | Stop the dashboard with Ctrl+C, copy the file, and start it again. |
| `-verify` reports a broken chain | A saved record was edited, removed, or reordered. | Treat this as a security incident. Keep the folder unchanged and investigate who had write access. |

## 12. Command reference

| Option | Effect |
|---|---|
| `-out <folder>` | Folder for saved results. The default is `results`. |
| `-baseline <file>` | Use this one baseline for every computer, overriding role and host list. |
| `-baselines <folder>` | Folder of baseline files that role-based selection uses. The default is `baseline`. |
| `-hosts <file>` | Scan the computers in this approved host list over the network. |
| `-host <name>` | With `-hosts`, scan only this computer from the list. |
| `-capture` | Record this computer's current configuration as its approved capture. |
| `-propose-exceptions` | With `-capture`, also draft an exception for every drifting check. |
| `-html=false` | Skip the HTML report and save only the JSON evidence. |
| `-serve` | Start the dashboard instead of scanning. |
| `-addr <address>` | Dashboard address. It must be a loopback address. The default is `127.0.0.1:8080`. |
| `-verify` | Check every evidence chain instead of scanning. |
