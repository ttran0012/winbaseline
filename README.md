# winbaseline

Windows configuration baseline and drift detection agent with tamper-evident,
cryptographically signed scan evidence. Written in Go.

**Windows Configuration Baseline and Drift Detection System** is a lightweight tool that scans Windows
computers against a documented security baseline (based on the CIS Benchmarks), reports every setting
that has drifted from the approved value, and saves the results as tamper-evident evidence. It reads
settings and writes evidence; it never changes a setting on any computer it reads, and installs
nothing on one.

## Documentation

- [User guide](docs/user-guide.md): install, scan, read results, approve configurations, exceptions, scanning many computers, the dashboard, troubleshooting, and a command reference.
- [Baseline configuration](docs/baseline-configuration.md): every check in the three baselines, why each one matters, severity, exceptions, approvals, versioning, and the NIST SP 800-171 mapping.
- [Test lab](lab/README.md): scripts that build a Hyper-V Active Directory lab for testing.

## Status

| Area | Status |
|---|---|
| Baselines (YAML) | v0.3.0: Windows 11 (90 checks), Windows Server 2022 domain controller (87), Windows Server 2025 member server (80); a computer's role picks one |
| Registry collector | Working |
| Services collector | Working (start type via Service Control Manager, query rights only) |
| Accounts collector | Working (built-in Guest/Administrator found by RID; Administrators group members found by SID) |
| Firewall collector | Working (Group Policy value overrides local value) |
| Audit policy collector | Working (subcategories matched by GUID; requires administrator) |
| Installed software collector | Working (prohibited-software patterns) |
| Comparison and severity | Working |
| Approved exceptions | Working (reported as EXCEPTION, not drift, until the approval expires) |
| Approved capture | Working: `-capture` records the configuration a computer was approved with, and scans report what CHANGED since then |
| Proposed exceptions | Working: `-capture -propose-exceptions` drafts an exception per drifting check for a person to fill in |
| Evidence storage | Working: JSON results hash-chained with SHA-256, never overwritten, `-verify` detects edits, deletions, and reordering |
| HTML report | Working: one self-contained file per scan, written beside the JSON evidence (`-html=false` to skip) |
| Local dashboard | Working: `-serve` on the loopback interface only, no scripts. Shows the saved evidence of every computer and can start a scan |
| Remote scanning (agentless) | Working: `-hosts` reads approved computers over the network as the account running it, no credentials stored, nothing installed. Audit policy cannot be read this way |
| Fleet dashboard and Start scan button | Working: the overview lists every computer worst-first, and a scan can be started from it |

## Build and run

Requires Go 1.27 or later on Windows; `go.mod` pins the patched `go1.27.2`
toolchain, which Go downloads automatically. Run from an elevated
(administrator) terminal to include the audit policy checks.

```powershell
go test ./...
go build -o driftscan.exe ./cmd/driftscan
.\driftscan.exe -baseline baseline\windows11-baseline.yaml -out results
.\driftscan.exe -verify -out results
```

Exit codes: `0` nothing to report, `1` drift found, `2` the run could not finish
or a computer answered nothing at all, `3` evidence verification failed,
including a capture folder that could no longer be trusted, `4` no drift, but
something changed since the approved capture. Task Scheduler can use these to
flag problems. When more than one applies, the louder one wins: `2` (nothing
could be read, so there are no findings) outranks `3` (the evidence itself is in
question), which outranks `1` (drift), which outranks `4` (a change policy still
allows). With `-hosts`, the code is the loudest of the computers scanned.

Each scan also writes an HTML report beside its JSON file, with the same base
name: `results\scan-HOST-20261018-121925-666.html`. It is one self-contained
file, with inline styles, no scripts, no web fonts, and no external links, so it
can be emailed or attached to an audit folder and still render years later. Results are
listed with anything changed since the capture first, then drift, errors,
approved exceptions, and compliant checks, most
severe first within each group, and the status is always spelled out as well as
colored so the page survives black-and-white printing. The footer names the JSON
file and its hash. The HTML is a view, not evidence: it is not part of the hash
chain, `-verify` ignores it, and deleting it changes nothing. Pass `-html=false`
to write only the JSON.

## Approved exceptions

Sometimes a deviation is deliberate: a department needs a tool the baseline
forbids, or a service cannot be disabled until a vendor system is replaced. A
top-level `exceptions:` list records those approvals, and the scan reports the
check as `EXCEPTION` rather than `DRIFT`.

```yaml
exceptions:
  - check: SW-002                 # ID of a check in this baseline
    hosts: [LAB-WIN11, LAB-WIN10] # computer names; omit to cover every host
    reason: "Helpdesk uses TeamViewer until the Intune rollout finishes"
    approved_by: "J. Lee, IT Manager"
    expires: "2026-12-31"         # last day it applies, YYYY-MM-DD
```

`reason`, `approved_by`, and a valid `expires` date are required, and `check`
must name a check in the same file; the baseline is rejected at load time
otherwise, so a typo in a check ID cannot silently excuse nothing. Host names
are matched case-insensitively.

An exception only ever downgrades drift. `COMPLIANT` and `ERROR` results are
left alone, and the deviation stays in the saved evidence with its reason and
approver in the result note, so an auditor sees both the finding and who
accepted it. Exceptions are counted separately in the summary and are not drift
for the exit code, so a host with only approved deviations exits `0` (or `4`, if
something also changed since its capture).

Approvals expire. From the day after `expires`, the check is drift again and the
note records that the exception expired, which gives the yearly review a list of
approvals to renew or retire rather than letting them accumulate.

## Scanning other computers

One computer at a time stops being useful at about the third server. `-hosts`
reads other computers over the network, without installing anything on them:

```powershell
copy hosts.example.yaml hosts.yaml   # then fill in the authorization block
.\driftscan.exe -hosts hosts.yaml -out results
.\driftscan.exe -hosts hosts.yaml -host SQL-02 -out results
```

Each computer gets its own folder of evidence, `results\<computer>\`, with its
own hash chain, because a chain has exactly one writer. `-verify` walks all of
them.

### No credentials are stored

driftscan reads a remote computer through the Windows APIs that take a computer
name: `RegConnectRegistry` for the registry, `OpenSCManager` for service start
types, and `NetUserEnum` / `NetLocalGroupGetMembers` for the built-in accounts
and the Administrators group. Those authenticate as **the account driftscan is
running as**, through Kerberos or NTLM. So:

- No password or credential is stored in a file, a registry key, or this
  program. There is nothing to steal from it.
- Nothing is installed or executed on the computer being read. It is not an
  agent, and it is not remote code execution.
- What a scan can see is exactly what that account was already allowed to see.
  To widen or narrow the scan, change the account's rights, not a config file.

On each computer being read, the account needs remote read access and the
Remote Registry service has to be running (it is disabled by default on
Windows 11; on servers, check your own policy before enabling it).

**Audit policy is the exception.** Windows has no remote audit policy API.
`auditpol.exe` takes no computer name and `AuditQuerySystemPolicy` answers only
for the machine it runs on. Those checks come back `ERROR` on a remote scan with
that reason in the note, rather than being quietly reported as compliant. To
cover them, run driftscan on the computer itself as a scheduled task. For the
same reason `-capture` refuses to run against a remote host: a capture that
recorded the audit policy as "unreadable" would be approving a blind spot.

### The host list is the authorization record

There is no flag that scans an address, a range, or a wildcard. A computer can
only be named in the host list, and the list will not load unless it records who
approved the scanning, when, for what, and until when:

```yaml
authorization:
  approved_by: "J. Lee, IT Manager"
  approved: "2026-10-21"
  expires: "2027-01-19"
  scope: "quarterly CIS review of the lab and file servers"

hosts:
  - name: SQL-02
    label: "database server"
  - name: DC-01
    label: "domain controller"
    skip: true
```

`approved_by` or `scope` left as `TODO` is refused, the same way an unfinished
exception is. Once `expires` passes, scanning stops until somebody renews it.
An approval with no end date is a standing permission to read other people's
servers, and this tool does not grant itself one. `-host` can only name a
computer that is already in the list, and the approval is printed at the top of
every run and recorded in the evidence.

The difference between a configuration scanner and a reconnaissance tool is
whose computers it was pointed at and who said yes, and that is a property of
the design, not of the operator's memory.

## Approved capture

The baseline answers one question: does this computer follow CIS policy? A
capture answers a different one: is this computer still configured the way it
was when someone signed off on it? Those come apart in practice. A setting can
satisfy the policy and still have been changed by somebody last Tuesday, and a
deviation the organization decided to live with is not news on every scan.

Record what a computer is approved with, from an elevated terminal:

```powershell
.\driftscan.exe -capture -out results
```

That reads every check and writes a capture into `results\captures\`: the host,
the time, the Windows account that took it, the baseline name and version, and
for each check a normalized value plus the policy status it had at the time. A
capture must run as administrator, because the audit policy cannot be read
without it and `unreadable` would otherwise be recorded as the approved
configuration; `-capture` refuses with exit code `2` rather than record that.

Normalized values are deterministic, so the same configuration always compares
equal: group members and installed programs are sorted, because the order
Windows returns them in is not a change, and a setting that is **not set** is a
different value from one that is **unreadable**, so a check that could not be
read is never approved as an absence.

Later scans pick up the newest capture for the computer by themselves and add a
change to every result:

| Change | Meaning |
|---|---|
| `UNCHANGED` | the value still matches the capture |
| `CHANGED` | it does not; the note records `was X, now Y` |
| `NEW_CHECK` | the baseline gained this check after the capture was taken |

The console grows a CHANGE column, the summary line gains `N changed since
capture <date>`, and the JSON and HTML reports carry the change along with the
capture's file name and hash, so the evidence says which approved configuration
the changes were measured against. The HTML report lists changed settings first.
A computer with no capture prints and saves exactly as it did before, with no
change field at all.

Captures live in their own append-only chain. `results\captures\chain.log` works
the same way as the scan ledger and `-verify` checks both. A scan verifies the
whole capture chain before it trusts anything in it, and checks each file's hash
before reading a single field, so an edited capture cannot push the scan on to
an older one; if the folder does not verify, the scan still runs and is saved,
but it reports no change at all. See the warning below for what that looks like.

**What the chain cannot catch.** Deleting the newest capture *together with* its
last line in `chain.log` leaves a shorter chain that still verifies perfectly:
every remaining record hashes correctly and links to the one before it, and
nothing inside the folder records how long the chain was supposed to be. A scan
then compares against the older capture it finds, with no sign that a newer
approval ever existed. The same hole applies to the scan ledger. Closing it
needs an anchor the computer does not control, such as the latest hash copied to
a write-once log, a signing service, or another machine. That is planned, and is
the same gap described under [Evidence chain](#evidence-chain) below.

### When a capture cannot be trusted

A tampered capture folder is no reason to stop watching the computer. It is a
reason to look harder at it. So a scan that cannot trust the captures does not
abort: the policy checks run and the evidence is saved as always, only without
any change comparison. The run then

- prints a block warning that the scan was **not** compared with a capture, with
  the reason and a pointer to `-verify`,
- records `"capture_status": "rejected: <reason>"` in the scan JSON, so the
  evidence says why it reports no change rather than leaving it to be read as
  nothing having changed,
- shows the same warning at the top of the HTML report, and
- exits `3`.

### Proposing exceptions

A computer being adopted usually has deviations that are going to be accepted
rather than fixed. Drafting them by hand is tedious, so:

```powershell
.\driftscan.exe -capture -propose-exceptions -out results
```

writes `results\captures\proposed-exceptions-<host>-<time>.yaml` with one entry
per check that is drifting: the check ID, this host, an expiry 90 days out, and
`TODO` for the reason and the approver. Baseline validation **rejects** `TODO`
in either field, so a draft cannot be adopted before a person has written down
why the deviation is acceptable and who accepted it. Edit the draft, delete the
entries you are not approving, and paste what is left into the baseline's
`exceptions:` list yourself. Checks already covered by an approved exception are
not proposed again, and the baseline file is never edited for you.

## Local dashboard

The saved JSON and the per-scan HTML report answer "what did this one scan
find?". Questions like "is this getting better or worse?" and "what changed
between Tuesday and today?" need the scans together, so:

```powershell
.\driftscan.exe -serve -out results
.\driftscan.exe -serve -addr 127.0.0.1:9000 -out results -baseline baseline\windows11-baseline.yaml
```

Add `-hosts hosts.yaml` to let the dashboard start scans of the computers that
list approves. Then open <http://127.0.0.1:8080/>. The pages are:

| Page | What it shows |
|---|---|
| Fleet | Every computer, most urgent first, with totals for computers needing attention, settings changed since capture, drift findings, and evidence status, plus a Needs attention list |
| Computer | One computer's state, its changes since the approved capture, its drift trend, and the **Approve as baseline** button |
| Results | One scan's checks grouped by type, filterable by status and severity through the query string: `?status=DRIFT&severity=high` |
| Compare | Two of one computer's scans side by side: new drift, fixed, still drifting, changed values |
| Scan | Start a scan and watch its progress. **Manage computers** adds, skips, or removes computers in the host list and tests remote access |
| Baseline | Every baseline, which computers use it, its checks, and the approved exceptions, marking any that expire within 30 days |
| Evidence | Re-runs the hash chain check over every ledger: each computer's scans, and the captures beside them |

The [user guide](docs/user-guide.md) walks through each page.

### Why it is built this way

A scan result is a list of the places a computer is weakest, and this dashboard
can now start a scan, which makes it worth being careful with:

- **Loopback only.** The server refuses to start unless `-addr` names a
  loopback IP: `127.0.0.1` or `[::1]`. `0.0.0.0`, a LAN address, and a bare
  `:8080` are all rejected, and so is `localhost`, since a name can be pointed
  anywhere. It is not a setting to be trusted to remember. The tool will not do
  it.
- **GET everywhere but one path.** Every page is a GET. The single exception is
  the form that starts a scan, a POST to `/scan/start` carrying a token from a
  page this server rendered; a request without that token, or from another
  origin, gets `403`. Anything else that is not a GET gets `405`.
- **What a started scan may do.** It reads settings and writes evidence into the
  results folder. It changes no setting on any computer, installs nothing, and
  holds no credentials: a remote read happens as the account the dashboard runs
  as. It will only name a computer the approved host list names, while that
  approval is in date, and it runs one scan at a time, so reloading the page
  cannot read every server twice.
- **A scan is reachable only through the ledger.** A page names a scan by file
  name, and that name has to appear in `chain.log` exactly as given, so no
  request can reach a file the scanner did not write. Names that are not plain
  file names are refused even if the ledger holds them. A file that no longer
  matches its recorded hash is still shown, but labeled `UNVERIFIED`.
- **Nothing is fetched from anywhere.** No scripts at all, no web fonts, no
  CDN: the content security policy is `default-src 'none'` with styles only
  from this server, so the dashboard works the same on a disconnected machine.
  The filters and the compare page are plain GET forms, and the trend chart is
  an SVG drawn in Go.
- **Not color alone.** Every status, severity, and change is written out as
  text next to its color, the tables use real headers and captions, and every
  form field has a label.

## Evidence chain

Each saved scan stores the SHA-256 hash of the previous scan, and `results\chain.log`
lists every scan with its own hash; captures keep an identical ledger of their own
in `results\captures\`. `-verify` recomputes every hash in both and reports the
first record that was edited, deleted, or taken out of order. Someone with write access
who rewrites every file and the log together could still forge the chain; signing the
latest hash or copying it off the computer is planned to close that gap.
## Testing and quality

| Test | How to run | Latest result |
|---|---|---|
| Unit and integration tests | `go test ./...` | All packages pass (Oct 23, 2026) |
| Dependency vulnerabilities | `govulncheck ./...` | Go 1.27.0 had 8 standard-library vulnerabilities in `net/http` and `html/template` reachable from the dashboard and reports; fixed by pinning `toolchain go1.27.2`. Rescan: no vulnerabilities affect this code (Oct 23, 2026) |
| Scan speed and memory | 5 local scans, 35 checks (baseline 0.2.0), `Start-Process` + peak working set | 0.08-0.15 s per scan, about 13.6 MB peak (target: under 60 s and 100 MB) |
| Smoke test (lab) | `lab\guest\Invoke-SmokeTest.ps1` inside a lab VM | 3 deliberate changes, evidence chain, and tamper detection, with PASS/FAIL per step |
| Drift detection (lab) | `lab\guest\Invoke-DriftTest.ps1` inside WS01 | 25 deliberate changes across all 7 check types; writes `results.csv` and a summary of detections, false alarms, and restore status |

## Project layout

```
cmd/driftscan/        command-line entry point
internal/baseline/    loads and validates the YAML baseline
internal/collect/     read-only collectors (registry, services, accounts, firewall, audit, software)
internal/compare/     compares observed values with expected values and with the capture
internal/capture/     records the approved configuration and drafts proposed exceptions
internal/fleet/       the approved host list for remote scans
internal/report/      console table, JSON evidence files, HTML report, and the hash chain
internal/scan/        reads one computer against the baseline and saves the evidence
internal/serve/       local dashboard: shows the evidence, and starts scans
baseline/             baseline definitions
docs/                 design documents and diagrams
```

## Safety

The tool never changes system settings. Run it in the lab VMs during development;
scan results can contain sensitive configuration details, so keep the `results`
folder restricted to administrators.
