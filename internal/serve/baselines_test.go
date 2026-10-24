package serve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/report"
)

const win11Baseline = `name: Windows 11 Enterprise Baseline
version: 0.3.0
checks:
  - id: REG-001
    title: UAC
    severity: high
    type: registry
    hive: HKLM
    path: A\B
    value: V
    operator: equals
    expected: "1"
`

const memberBaseline = `name: Member Server Baseline
version: 0.1.0
checks:
  - id: SVC-001
    title: Spooler disabled
    severity: medium
    type: service
    service: Spooler
    expected: disabled_or_absent
exceptions:
  - check: SVC-001
    reason: "print server until the Q2 migration"
    approved_by: "J. Lee"
    expires: "2099-12-31"
`

// saveScanNamed saves one scan into dir, recorded against the named baseline.
func saveScanNamed(t *testing.T, dir, host, baselineName string) {
	t.Helper()
	rs := results(false, "")
	s := report.Scan{
		Host: host, StartedAt: testNow.Add(-time.Hour), Elevated: true,
		BaselineName: baselineName, BaselineVersion: "1.0",
		Results: rs, Summary: report.Summarize(rs),
	}
	if _, err := report.Save(dir, s); err != nil {
		t.Fatal(err)
	}
}

func writeBaselineFolder(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"windows11-baseline.yaml":              win11Baseline,
		"windows-server-2025-ms-baseline.yaml": memberBaseline,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The Baseline page lists every baseline in the folder, its checks by type, its
// exceptions, and which computers are read against it.
func TestBaselinePageListsEveryBaselineAndItsComputers(t *testing.T) {
	resultsDir := t.TempDir()
	bdir := writeBaselineFolder(t)

	// A workstation scanned against the Windows 11 baseline, a server against the
	// member-server one.
	saveScanNamed(t, resultsDir, "WS01", "Windows 11 Enterprise Baseline")
	saveScanNamed(t, filepath.Join(resultsDir, "SRV01"), "SRV01", "Member Server Baseline")

	s := New(Options{Dir: resultsDir, BaselineDir: bdir, Now: func() time.Time { return testNow }})
	body := get(t, s, "/baseline").Body.String()

	for _, want := range []string{
		"Windows 11 Enterprise Baseline", "Member Server Baseline",
		"Checks by type", "print server until the Q2 migration",
		"WS01", "SRV01",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the Baseline page is missing %q", want)
		}
	}

	// Each computer is shown under the baseline its scan recorded: SRV01 sits
	// with the member-server baseline, not the workstation one.
	member := body[strings.Index(body, "Member Server Baseline"):]
	if !strings.Contains(member, "SRV01") {
		t.Error("SRV01 should be listed under the member-server baseline")
	}
}

// With -baseline forcing one file, the page shows that single baseline.
func TestBaselinePageWithAForcedBaseline(t *testing.T) {
	resultsDir := t.TempDir()
	bdir := writeBaselineFolder(t)
	forced := filepath.Join(bdir, "windows11-baseline.yaml")

	s := New(Options{Dir: resultsDir, BaselineDir: bdir, BaselineFile: forced,
		Now: func() time.Time { return testNow }})
	body := get(t, s, "/baseline").Body.String()

	if !strings.Contains(body, "Windows 11 Enterprise Baseline") {
		t.Error("the forced baseline should be shown")
	}
	if strings.Contains(body, "Member Server Baseline") {
		t.Error("a forced baseline governs every computer, so no other should be listed")
	}
}
