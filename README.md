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
| Approved exceptions | Planned |
| Evidence storage | Working: JSON results hash-chained with SHA-256, never overwritten, `-verify` detects edits, deletions, and reordering |
| HTML report | Planned |

## Build and run

Requires Go 1.27 or later on Windows. Run from an elevated (administrator)
terminal to include the audit policy checks.

```powershell
go test ./...
go build -o driftscan.exe ./cmd/driftscan
.\driftscan.exe -baseline baseline\windows11-baseline.yaml -out results
.\driftscan.exe -verify -out results
```

Exit codes: `0` all compliant, `1` drift found, `2` the scan could not run,
`3` evidence verification failed. Task Scheduler can use these to flag problems.

## Evidence chain

Each saved scan stores the SHA-256 hash of the previous scan, and `results\chain.log`
lists every scan with its own hash. `-verify` recomputes every hash and reports the
first scan that was edited, deleted, or taken out of order. Someone with write access
who rewrites every file and the log together could still forge the chain; signing the
latest hash or copying it off the computer is planned to close that gap.
## Project layout

```
cmd/driftscan/        command-line entry point
internal/baseline/    loads and validates the YAML baseline
internal/collect/     read-only collectors (registry, services, accounts, firewall, audit, software)
internal/compare/     compares observed values with expected values
internal/report/      console table, JSON evidence files, and the hash chain
baseline/             baseline definitions
docs/                 design documents and diagrams
```

## Safety

The tool never changes system settings. Run it in the lab VMs during development;
scan results can contain sensitive configuration details, so keep the `results`
folder restricted to administrators.
