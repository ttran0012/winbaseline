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
| Baseline format (YAML) | Draft v0.1.0, 14 registry checks |
| Registry collector | In-Progress... |
| Services, firewall, audit policy, accounts, software collectors | Planned |
| Comparison and severity | Working (equals / lte / gte, Windows defaults) |
| Evidence storage | JSON results + SHA-256 hash (hash chain planned) |
| HTML report | Planned |

## Build and run

Requires Go 1.27 or later on Windows.

```powershell
go test ./...
go build -o driftscan.exe ./cmd/driftscan
.\driftscan.exe -baseline baseline\windows11-baseline.yaml -out results
```

The exit code is `0` when every check is compliant and `1` when drift is found,
so the tool can run from Task Scheduler and flag problems.

## Project layout

```
cmd/driftscan/        command-line entry point
internal/baseline/    loads and validates the YAML baseline
internal/collect/     read-only collectors (registry so far)
internal/compare/     compares observed values with expected values
internal/report/      console table and JSON evidence files
baseline/             baseline definitions
docs/                 design documents and diagrams
```

## Safety

The tool never changes system settings. Run it in the lab VMs during development;
scan results can contain sensitive configuration details, so keep the `results`
folder restricted to administrators.
