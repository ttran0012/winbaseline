# winbaseline

Windows configuration baseline and drift detection agent with tamper-evident,
cryptographically signed scan evidence. Written in Go.

**Windows Configuration Baseline and Drift Detection System** is a lightweight, read-only tool that scans a Windows computer against a documented
security baseline (based on the CIS Benchmarks), reports every setting that has
drifted from the approved value, and saves the results as evidence for later review.

· IT599 Capstone ·

## Status

| Area | Status |
|---|---|
| Baseline format (YAML) | v0.2.0, 35 checks across 7 check types |
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

## Build and run

Requires Go 1.27 or later on Windows. Run from an elevated (administrator)
terminal to include the audit policy checks.

```powershell
go test ./...
go build -o driftscan.exe ./cmd/driftscan
.\driftscan.exe -baseline baseline\windows11-baseline.yaml -out results
.\driftscan.exe -verify -out results
```

Exit codes: `0` nothing to report, `1` drift found, `2` the run could not
finish, `3` evidence verification failed, including a capture folder that could
no longer be trusted, `4` no drift, but something changed since the approved
capture. Task Scheduler can use these to flag problems. When more than one
applies, the louder one wins: `3` (the evidence itself is in question) outranks
`1` (drift), which outranks `4` (a change policy still allows).

Each scan also writes an HTML report beside its JSON file, with the same base
name: `results\scan-HOST-20261018-121925-666.html`. It is one self-contained
file — inline styles, no scripts, no web fonts, no external links — so it can be
emailed or attached to an audit folder and still render years later. Results are
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
needs an anchor the computer does not control — the latest hash copied to a
write-once log, a signing service, or another machine — which is planned, and is
the same gap described under [Evidence chain](#evidence-chain) below.

### When a capture cannot be trusted

A tampered capture folder is no reason to stop watching the computer — it is a
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

## Evidence chain

Each saved scan stores the SHA-256 hash of the previous scan, and `results\chain.log`
lists every scan with its own hash; captures keep an identical ledger of their own
in `results\captures\`. `-verify` recomputes every hash in both and reports the
first record that was edited, deleted, or taken out of order. Someone with write access
who rewrites every file and the log together could still forge the chain; signing the
latest hash or copying it off the computer is planned to close that gap.
## Project layout

```
cmd/driftscan/        command-line entry point
internal/baseline/    loads and validates the YAML baseline
internal/collect/     read-only collectors (registry, services, accounts, firewall, audit, software)
internal/compare/     compares observed values with expected values and with the capture
internal/capture/     records the approved configuration and drafts proposed exceptions
internal/report/      console table, JSON evidence files, HTML report, and the hash chain
baseline/             baseline definitions
docs/                 design documents and diagrams
```

## Safety

The tool never changes system settings. Run it in the lab VMs during development;
scan results can contain sensitive configuration details, so keep the `results`
folder restricted to administrators.
