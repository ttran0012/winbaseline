package serve

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/capture"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// approvalForm is a complete, valid approval of one scan of the local computer.
func approvalForm(s *Server, file string) url.Values {
	return url.Values{
		"csrf":     {s.csrf},
		"host":     {""},
		"file":     {file},
		"note":     {"reviewed after the October rebuild"},
		"reviewed": {"1"},
	}
}

// serverWithScan writes one scan to the local results folder and returns a
// dashboard over it, with a clock the test controls.
func serverWithScan(t *testing.T, results []compare.Result) (*Server, string, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.yaml")
	if err := os.WriteFile(baselinePath, []byte(testBaseline), 0o600); err != nil {
		t.Fatal(err)
	}
	s := report.Scan{
		Host: "LAB-WIN11", StartedAt: testNow.Add(-time.Hour), Elevated: true,
		BaselineName: "Test Baseline", BaselineVersion: "9.9.9",
		Results: results, Summary: report.Summarize(results),
	}
	entry, err := report.Save(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	clock := testNow
	srv := New(Options{Dir: dir, BaselineFile: baselinePath, Now: func() time.Time { return clock }})
	return srv, entry.File, &clock
}

// Approving a reviewed scan records a capture the next scan is measured against.
func TestApproveFromVerifiedScan(t *testing.T) {
	s, saved := testServer(t)
	file := saved[len(saved)-1].File

	// The review page renders what is about to be approved.
	rec := get(t, s, "/approve?file="+file)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET review = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"Approve as baseline", "Record the approval", `name="note"`,
		`name="reviewed"`, "I reviewed these results"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("review page is missing %q", want)
		}
	}

	rec = postPath(t, s, approvePath, approvalForm(s, file), nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST approve = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/computer") {
		t.Errorf("redirected to %q, want the computer page", loc)
	}

	hist := captureHistory(s.dir)
	if len(hist) != 1 {
		t.Fatalf("approval history has %d entries, want 1", len(hist))
	}
	a := hist[0]
	switch {
	case a.Note != "reviewed after the October rebuild":
		t.Errorf("note = %q", a.Note)
	case a.SourceScan != file:
		t.Errorf("source scan = %q, want %q", a.SourceScan, file)
	case a.By == "":
		t.Error("the approval records no approver")
	case !a.Verified:
		t.Error("the saved approval does not verify")
	case a.FromCapture:
		t.Error("an approval from a scan should not read as a -capture record")
	}
}

// Evidence that does not verify is not a sound basis for a baseline.
func TestApproveRefusesATamperedScan(t *testing.T) {
	s, saved := testServer(t)
	file := saved[len(saved)-1].File

	path := filepath.Join(s.dir, file)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Change the bytes so the file no longer matches the hash the ledger holds.
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	rec := postPath(t, s, approvePath, approvalForm(s, file), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST approve of a tampered scan = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "does not verify") {
		t.Errorf("the refusal should say the evidence does not verify, got %q", rec.Body.String())
	}
	if len(captureHistory(s.dir)) != 0 {
		t.Error("a tampered scan was approved anyway")
	}
}

// The note and the confirmation are both required, and the note is bounded.
func TestApproveRefusesMissingNoteOrConfirmation(t *testing.T) {
	s, saved := testServer(t)
	file := saved[len(saved)-1].File

	cases := map[string]func(url.Values){
		"no note":       func(f url.Values) { f.Del("note") },
		"blank note":    func(f url.Values) { f.Set("note", "   ") },
		"note too long": func(f url.Values) { f.Set("note", strings.Repeat("x", noteMax+1)) },
		"not reviewed":  func(f url.Values) { f.Del("reviewed") },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := approvalForm(s, file)
			edit(f)
			if rec := postPath(t, s, approvePath, f, nil); rec.Code != http.StatusForbidden {
				t.Errorf("POST = %d, want 403", rec.Code)
			}
		})
	}
	if len(captureHistory(s.dir)) != 0 {
		t.Error("an incomplete approval was recorded")
	}
}

// Approving is a write, so it needs a form this server rendered.
func TestApproveRefusesCSRFFailures(t *testing.T) {
	s, saved := testServer(t)
	file := saved[len(saved)-1].File

	cases := []struct {
		name    string
		form    func(url.Values)
		headers map[string]string
	}{
		{"no token", func(f url.Values) { f.Del("csrf") }, nil},
		{"wrong token", func(f url.Values) { f.Set("csrf", "nope") }, nil},
		{"cross-site", func(url.Values) {}, map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"foreign origin", func(url.Values) {}, map[string]string{"Origin": "http://evil.example"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := approvalForm(s, file)
			tc.form(f)
			if rec := postPath(t, s, approvePath, f, tc.headers); rec.Code != http.StatusForbidden {
				t.Errorf("POST = %d, want 403", rec.Code)
			}
		})
	}
	if len(captureHistory(s.dir)) != 0 {
		t.Error("an untrusted approval was recorded")
	}
}

// Unreadable checks have to be explicitly left out, and are then recorded as
// excluded rather than approved as "unreadable".
func TestApproveErrorsNeedExplicitExclusion(t *testing.T) {
	s, file, _ := serverWithScan(t, []compare.Result{
		{ID: "REG-001", Title: "UAC", Severity: "high", Status: compare.Compliant, Normalized: "1"},
		{ID: "AUD-001", Title: "Audit logon", Severity: "medium", Status: compare.Error,
			Normalized: "unreadable", Note: "audit policy cannot be read remotely"},
	})

	// Without the exclusion, refused and the unreadable check is named.
	rec := postPath(t, s, approvePath, approvalForm(s, file), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without exclusion = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "AUD-001") {
		t.Errorf("the refusal should name the unreadable check, got %q", rec.Body.String())
	}
	if len(captureHistory(s.dir)) != 0 {
		t.Fatal("the scan was approved without confirming the exclusion")
	}

	// With it, approved, and the excluded check is recorded, not stored as a value.
	f := approvalForm(s, file)
	f.Set("exclude_errors", "1")
	if rec := postPath(t, s, approvePath, f, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST with exclusion = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	hist := captureHistory(s.dir)
	if len(hist) != 1 || len(hist[0].Excluded) != 1 || hist[0].Excluded[0] != "AUD-001" {
		t.Fatalf("excluded = %v, want [AUD-001]", hist)
	}
	loaded, err := capture.Latest(captureFolder(s.dir), "LAB-WIN11")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Capture.Values()["AUD-001"]; ok {
		t.Error("the unreadable check was recorded as an approved value")
	}
}

// After approval the next scan is measured against the new capture, and the
// computer is no longer NOT APPROVED.
func TestNextScanComparesAgainstTheApprovedBaseline(t *testing.T) {
	s, saved := testServer(t)
	host := "LAB-WIN11"

	// Before: no capture, so the computer reads NOT APPROVED.
	if got := stateOf(s, host); got != StateNotApproved {
		t.Fatalf("before approval state = %q, want %q", got, StateNotApproved)
	}

	rec := postPath(t, s, approvePath, approvalForm(s, saved[len(saved)-1].File), nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST approve = %d, want 303: %s", rec.Code, rec.Body.String())
	}

	// capture.Latest is exactly what the next scan loads to compare against.
	loaded, err := capture.Latest(captureFolder(s.dir), host)
	if err != nil || loaded == nil {
		t.Fatalf("capture.Latest = %v, %v; want the approval", loaded, err)
	}
	if loaded.Capture.Approval == nil {
		t.Error("the loaded capture records no approval")
	}
	values := loaded.Capture.Values()
	// SVC-001 was drifting and approved as-is, so an identical reading is
	// unchanged and a different one is a change.
	if values["SVC-001"] != "manual" {
		t.Fatalf("approved SVC-001 value = %q, want manual", values["SVC-001"])
	}
	same := compare.ApplyChange(compare.Result{ID: "SVC-001", Status: compare.Drift}, values["SVC-001"], "manual", true)
	if same.Change != compare.Unchanged {
		t.Errorf("identical reading change = %q, want UNCHANGED", same.Change)
	}
	moved := compare.ApplyChange(compare.Result{ID: "SVC-001", Status: compare.Drift}, values["SVC-001"], "automatic", true)
	if moved.Change != compare.Changed {
		t.Errorf("moved reading change = %q, want CHANGED", moved.Change)
	}

	// After: the computer is no longer NOT APPROVED; its drift shows instead.
	if got := stateOf(s, host); got != StateDrift {
		t.Errorf("after approval state = %q, want %q", got, StateDrift)
	}
}

// Every approval is kept, so the history is a record of each sign-off.
func TestApprovalHistoryListsEveryApproval(t *testing.T) {
	dir, baselinePath, saved := testResults(t)
	clock := testNow
	s := New(Options{Dir: dir, BaselineFile: baselinePath, Now: func() time.Time { return clock }})

	if rec := postPath(t, s, approvePath, approvalForm(s, saved[1].File), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("first approval = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	clock = clock.Add(time.Hour) // a later approval needs a later moment to be its own record
	if rec := postPath(t, s, approvePath, approvalForm(s, saved[2].File), nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("second approval = %d, want 303: %s", rec.Code, rec.Body.String())
	}

	hist := captureHistory(dir)
	if len(hist) != 2 {
		t.Fatalf("history has %d entries, want 2", len(hist))
	}
	// Newest first: the second approval is the current one.
	if hist[0].SourceScan != saved[2].File || hist[1].SourceScan != saved[1].File {
		t.Errorf("history source scans = %q, %q; want %q, %q",
			hist[0].SourceScan, hist[1].SourceScan, saved[2].File, saved[1].File)
	}
	for _, a := range hist {
		if !a.Verified {
			t.Errorf("approval %s does not verify", a.File)
		}
	}
	// The whole capture chain still verifies with both approvals in it.
	if n, err := report.Verify(captureFolder(dir)); err != nil || n != 2 {
		t.Fatalf("capture chain verify = %d, %v; want 2, nil", n, err)
	}

	// The computer page shows both.
	body := get(t, s, "/computer").Body.String()
	if !strings.Contains(body, "Approval history") ||
		!strings.Contains(body, saved[1].File) || !strings.Contains(body, saved[2].File) {
		t.Error("the computer page does not list every approval")
	}
}

// stateOf finds the fleet state of one computer by host name.
func stateOf(s *Server, host string) string {
	for _, c := range s.fleet() {
		if strings.EqualFold(c.Host, host) {
			return c.State()
		}
	}
	return "not found"
}
