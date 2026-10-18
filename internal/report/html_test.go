package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/compare"
)

func testScan(results []compare.Result) Scan {
	return Scan{
		Host:            "LAB-WIN11",
		StartedAt:       time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC),
		Elevated:        true,
		BaselineName:    "Windows 11 Enterprise Baseline",
		BaselineVersion: "0.2.0",
		Summary:         Summarize(results),
		Results:         results,
	}
}

func render(t *testing.T, s Scan, e ChainEntry) string {
	t.Helper()
	var out strings.Builder
	if err := WriteHTML(&out, s, e); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// A collector reads names and values off the scanned computer, and a service
// display name or an installed program can contain anything at all, so nothing
// from a result may reach the page as markup.
func TestHTMLEscapesResultValues(t *testing.T) {
	const payload = `<script>alert("drift")</script>`
	s := testScan([]compare.Result{{
		ID:       payload,
		Title:    "Prohibited software " + payload,
		Severity: payload,
		Location: "Installed software matching: " + payload,
		Expected: "not installed",
		Actual:   payload,
		Status:   compare.Drift,
		Note:     "found " + payload,
	}})
	s.Host = payload
	page := render(t, s, ChainEntry{File: payload, Hash: payload, PreviousHash: payload})

	if strings.Contains(page, "<script") || strings.Contains(page, "</script") {
		t.Error("page contains an unescaped script tag")
	}
	if strings.Contains(page, `alert("drift")`) {
		t.Error("page contains the payload with unescaped quotes")
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Error("page does not contain the escaped payload; was it dropped instead of escaped?")
	}
	// Severity drives a CSS class, so an unexpected value must not reach the attribute.
	if !strings.Contains(page, `class="sev other"`) {
		t.Error("an unrecognized severity should fall back to a known class")
	}
}

func TestHTMLShowsSummaryNumbers(t *testing.T) {
	var results []compare.Result
	add := func(n int, status, severity string) {
		for i := 0; i < n; i++ {
			results = append(results, compare.Result{ID: status, Status: status, Severity: severity})
		}
	}
	add(4, compare.Compliant, "low")
	add(3, compare.Drift, "high")
	add(2, compare.Exception, "medium")
	add(1, compare.Error, "high")

	s := testScan(results)
	if s.Summary != (Summary{Total: 10, Compliant: 4, Drift: 3, Exceptions: 2, Errors: 1}) {
		t.Fatalf("test setup: unexpected summary %+v", s.Summary)
	}
	page := render(t, s, ChainEntry{File: "scan.json"})

	// Each count is checked together with its label, so transposed numbers fail.
	for _, want := range []string{
		`<span class="n">10</span><span class="k">Checks</span>`,
		`<span class="n">4</span><span class="k">Compliant</span>`,
		`<span class="n">3</span><span class="k">Drift</span>`,
		`<span class="n">2</span><span class="k">Exceptions</span>`,
		`<span class="n">1</span><span class="k">Errors</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("summary is missing %s", want)
		}
	}
	for _, want := range []string{"LAB-WIN11", "Windows 11 Enterprise Baseline", "v0.2.0", "Yes"} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not show %q", want)
		}
	}
}

func TestHTMLOmitsExceptionCountWhenThereAreNone(t *testing.T) {
	page := render(t, testScan([]compare.Result{{Status: compare.Compliant}}), ChainEntry{})
	if strings.Contains(page, "Exceptions</span>") {
		t.Error("the exceptions count should only appear when the scan has one")
	}
}

func TestHTMLStatesWhenNotAdministrator(t *testing.T) {
	s := testScan([]compare.Result{{Status: compare.Error}})
	s.Elevated = false
	if page := render(t, s, ChainEntry{}); !strings.Contains(page, "some settings could not be read") {
		t.Error("page should say that a scan without administrator rights is incomplete")
	}
}

func TestSortForReport(t *testing.T) {
	// Each ID names the position it belongs in, so the want list below reads as
	// the report order itself.
	in := []compare.Result{
		{ID: "compliant-high", Status: compare.Compliant, Severity: "high"},
		{ID: "exception-low", Status: compare.Exception, Severity: "low"},
		{ID: "drift-medium", Status: compare.Drift, Severity: "medium"},
		{ID: "error-low", Status: compare.Error, Severity: "low"},
		{ID: "drift-low", Status: compare.Drift, Severity: "low"},
		{ID: "unknown", Status: "SOMETHING ELSE", Severity: "high"},
		{ID: "drift-high", Status: compare.Drift, Severity: "high"},
		{ID: "error-high", Status: compare.Error, Severity: "high"},
		{ID: "exception-high", Status: compare.Exception, Severity: "high"},
		{ID: "compliant-low", Status: compare.Compliant, Severity: "low"},
	}
	want := []string{
		"drift-high", "drift-medium", "drift-low",
		"error-high", "error-low",
		"exception-high", "exception-low",
		"compliant-high", "compliant-low",
		"unknown",
	}
	got := sortForReport(in)
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("position %d = %s, want %s", i, got[i].ID, id)
		}
	}
	// The saved JSON is hashed in the baseline's order, so sorting must copy.
	if in[0].ID != "compliant-high" {
		t.Error("sortForReport reordered the results it was given")
	}
}

func TestHTMLRowsFollowReportOrder(t *testing.T) {
	page := render(t, testScan([]compare.Result{
		{ID: "C-1", Status: compare.Compliant, Severity: "low"},
		{ID: "D-1", Status: compare.Drift, Severity: "high"},
	}), ChainEntry{})
	if strings.Index(page, "D-1") > strings.Index(page, "C-1") {
		t.Error("drift should be listed before compliant results")
	}
}

func TestHTMLIsSelfContained(t *testing.T) {
	page := render(t, testScan([]compare.Result{{ID: "REG-001", Status: compare.Drift, Severity: "high"}}),
		ChainEntry{File: "scan.json", Hash: "abc", PreviousHash: "def"})
	for _, forbidden := range []string{"<script", "<link", "<iframe", "<img", "http://", "https://", "@import", "url("} {
		if strings.Contains(page, forbidden) {
			t.Errorf("page is not self-contained: it contains %q", forbidden)
		}
	}
	if !strings.Contains(page, "<style>") {
		t.Error("page should carry its own inline stylesheet")
	}
}

func TestHTMLFooterNamesTheEvidence(t *testing.T) {
	e := ChainEntry{
		File:         "scan-LAB-WIN11-20261018-093000-000.json",
		Hash:         strings.Repeat("a", 64),
		PreviousHash: strings.Repeat("b", 64),
	}
	page := render(t, testScan([]compare.Result{{Status: compare.Drift}}), e)
	for _, want := range []string{e.File, e.Hash, e.PreviousHash, "tamper-evident record", "not part of the chain"} {
		if !strings.Contains(page, want) {
			t.Errorf("footer does not contain %q", want)
		}
	}
}

func TestSaveHTMLWritesBesideTheJSONAndStaysOutOfTheChain(t *testing.T) {
	dir := t.TempDir()
	s := testScan([]compare.Result{{ID: "REG-001", Status: compare.Drift, Severity: "high"}})
	entry, err := Save(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	path, err := SaveHTML(dir, s, entry)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSuffix(entry.File, ".json") + ".html"; filepath.Base(path) != want {
		t.Errorf("HTML file is %s, want %s", filepath.Base(path), want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	// The chain covers the JSON only: the ledger must not mention the HTML file,
	// and the chain must still verify with it sitting in the same folder.
	log, err := os.ReadFile(filepath.Join(dir, ChainLog))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), ".html") {
		t.Error("the HTML report should not be listed in the evidence chain")
	}
	if n, err := Verify(dir); err != nil || n != 1 {
		t.Fatalf("Verify = %d, %v; want 1, nil", n, err)
	}
	if _, err := SaveHTML(dir, s, entry); err == nil {
		t.Error("a second write to the same name should be refused")
	}
}

// capturedScan is a scan that was compared with an approved capture.
func capturedScan(results []compare.Result) Scan {
	s := testScan(results)
	s.Capture = &CaptureRef{
		File:       "capture-LAB-WIN11-20261001-080000-000.json",
		Hash:       strings.Repeat("c", 64),
		CapturedAt: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC),
	}
	return s
}

func TestHTMLShowsChangesWhenComparedWithACapture(t *testing.T) {
	s := capturedScan([]compare.Result{
		{ID: "SVC-001", Status: compare.Drift, Severity: "high", Change: compare.Changed,
			Note: `changed since capture: was "disabled", now "manual"`},
		{ID: "SVC-002", Status: compare.Compliant, Severity: "low", Change: compare.Unchanged},
		{ID: "SVC-003", Status: compare.Compliant, Severity: "low", Change: compare.NewCheck},
	})
	page := render(t, s, ChainEntry{File: "scan.json", Hash: "abc", PreviousHash: "def"})

	for _, want := range []string{
		"<th>Change</th>",
		`<span class="badge changed">CHANGED</span>`,
		`<span class="badge unchanged">UNCHANGED</span>`,
		`<span class="badge new-check">NEW_CHECK</span>`,
		`<span class="n">1</span><span class="k">Changed</span>`,
		"was &#34;disabled&#34;, now &#34;manual&#34;",
		s.Capture.File,
		s.Capture.Hash,
		"Approved capture",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q", want)
		}
	}
}

func TestHTMLWithoutACaptureHasNoChangeColumn(t *testing.T) {
	page := render(t, testScan([]compare.Result{{ID: "SVC-001", Status: compare.Drift, Severity: "high"}}),
		ChainEntry{File: "scan.json"})
	for _, forbidden := range []string{"<th>Change</th>", "Approved capture", "Capture file"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("a scan with no capture should not show %q", forbidden)
		}
	}
}

// Something changed since the computer was approved is the first thing the
// reader needs, even when the baseline itself is satisfied.
func TestSortForReportPutsChangesFirst(t *testing.T) {
	in := []compare.Result{
		{ID: "drift-high", Status: compare.Drift, Severity: "high", Change: compare.Unchanged},
		{ID: "compliant-low-changed", Status: compare.Compliant, Severity: "low", Change: compare.Changed},
		{ID: "error-high", Status: compare.Error, Severity: "high", Change: compare.Unchanged},
		{ID: "drift-low-changed", Status: compare.Drift, Severity: "low", Change: compare.Changed},
		{ID: "drift-high-changed", Status: compare.Drift, Severity: "high", Change: compare.Changed},
	}
	want := []string{
		"drift-high-changed", "drift-low-changed", "compliant-low-changed",
		"drift-high", "error-high",
	}
	got := sortForReport(in)
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("position %d = %s, want %s", i, got[i].ID, id)
		}
	}
}

// The HTML report is the copy that gets emailed and filed, so it has to carry
// the warning too: a reader must not take a page with no change column as proof
// that nothing changed.
func TestHTMLShowsARejectedCapture(t *testing.T) {
	s := testScan([]compare.Result{{ID: "SVC-001", Status: compare.Drift, Severity: "high"}})
	s.CaptureStatus = CaptureStatusRejected + "capture chain broken after 1 valid capture(s): record 2 was modified"
	page := render(t, s, ChainEntry{File: "scan.json", Hash: "abc", PreviousHash: "def"})

	for _, want := range []string{
		`<p class="alert">`,
		"Capture not used",
		"capture chain broken after 1 valid capture(s)",
		"says nothing about what changed",
		"SVC-001", // the policy results are still there
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	for _, forbidden := range []string{"<th>Change</th>", "Approved capture", "Capture file"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("a rejected capture should not produce %q", forbidden)
		}
	}
}

func TestHTMLHasNoAlertWhenNothingIsWrong(t *testing.T) {
	page := render(t, testScan([]compare.Result{{ID: "SVC-001", Status: compare.Compliant, Severity: "low"}}), ChainEntry{})
	if strings.Contains(page, `class="alert"`) {
		t.Error("a healthy scan should not show an alert banner")
	}
}
