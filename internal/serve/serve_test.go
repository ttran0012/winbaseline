package serve

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

var testNow = time.Date(2026, 10, 18, 14, 0, 0, 0, time.UTC)

// testBaseline is a baseline the dashboard can read: two checks, one approved
// exception that has expired and one that is about to.
const testBaseline = `
name: Test Baseline
version: 9.9.9
benchmark: test only
checks:
  - id: REG-001
    title: "User Account Control: Admin Approval Mode"
    cis: "2.3.17.1"
    severity: high
    type: registry
    hive: HKLM
    path: SOFTWARE\Policies
    value: EnableLUA
    operator: equals
    expected: "1"
  - id: SVC-001
    title: "UPnP Device Host is disabled"
    severity: low
    type: service
    service: upnphost
    expected: disabled
exceptions:
  - check: SVC-001
    hosts: [LAB-WIN11]
    reason: "vendor app needs the service until migration"
    approved_by: "J. Lee, IT Manager"
    expires: "2026-10-30"
  - check: REG-001
    reason: "temporary, for the imaging bench"
    approved_by: "A. Nguyen"
    expires: "2026-09-01"
`

// results builds one scan's results. drift says whether SVC-001 is drifting,
// and changed whether it moved since the capture.
func results(drift bool, change string) []compare.Result {
	svc := compare.Result{
		ID: "SVC-001", Title: "UPnP Device Host is disabled", Severity: "low",
		Location: "Service: upnphost", Expected: "disabled", Actual: "disabled",
		Status: compare.Compliant, Change: change,
	}
	if drift {
		svc.Status, svc.Actual = compare.Drift, "manual"
	}
	if change == compare.Changed {
		svc.Note = `changed since capture: was "disabled", now "manual"`
	}
	return []compare.Result{
		{
			ID: "REG-001", Title: "User Account Control: Admin Approval Mode", Severity: "high",
			Location: `HKLM\SOFTWARE\Policies\EnableLUA`, Expected: "1", Actual: "1",
			Status: compare.Compliant, Change: firstNonEmpty(change, ""),
		},
		svc,
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// testResults writes a results folder holding three scans: a clean one, one
// where a check started drifting, and a newest one that was compared with a
// capture and found the same check changed. It returns the folder, the baseline
// path, and the saved scans oldest first.
func testResults(t *testing.T) (dir, baselinePath string, saved []report.ChainEntry) {
	t.Helper()
	dir = t.TempDir()
	baselinePath = filepath.Join(dir, "baseline.yaml")
	if err := os.WriteFile(baselinePath, []byte(testBaseline), 0o600); err != nil {
		t.Fatal(err)
	}

	scans := []report.Scan{
		{Results: results(false, "")},
		{Results: results(true, "")},
		{
			Capture: &report.CaptureRef{
				File:       "capture-LAB-WIN11-20261001-080000-000.json",
				Hash:       strings.Repeat("c", 64),
				CapturedAt: testNow.Add(-17 * 24 * time.Hour),
			},
			Results: results(true, compare.Changed),
		},
	}
	for i, s := range scans {
		s.Host = "LAB-WIN11"
		s.StartedAt = testNow.Add(-time.Duration(len(scans)-i) * time.Hour)
		s.Elevated = true
		s.BaselineName, s.BaselineVersion = "Test Baseline", "9.9.9"
		s.Summary = report.Summarize(s.Results)
		entry, err := report.Save(dir, s)
		if err != nil {
			t.Fatal(err)
		}
		saved = append(saved, entry)
	}
	return dir, baselinePath, saved
}

func testServer(t *testing.T) (*Server, []report.ChainEntry) {
	t.Helper()
	dir, baselinePath, saved := testResults(t)
	return New(Options{
		Dir:          dir,
		BaselinePath: baselinePath,
		Now:          func() time.Time { return testNow },
	}), saved
}

// get asks for a path and returns the response.
func get(t *testing.T, s *Server, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestPagesRender(t *testing.T) {
	s, saved := testServer(t)
	newest := saved[len(saved)-1].File

	tests := []struct {
		name   string
		target string
		want   []string
	}{
		{"overview lists the computers", "/", []string{
			"Computers", "LAB-WIN11", "THIS COMPUTER", "Start a scan",
			"Evidence chain", "Verified",
		}},
		{"scans list, with this computer's trend and changes", "/scans", []string{
			"Scans", "saved scan(s)", newest, "Results",
			"Changed since the approved capture", "Drift trend", "<svg",
		}},
		{"scan detail", "/scan?file=" + newest, []string{
			"Scan results", "SVC-001", "DRIFT", "CHANGED", "Check type", newest,
		}},
		{"compare", "/compare", []string{"Compare two scans", "New drift", "Fixed", "Still drifting", "Changed values"}},
		{"baseline", "/baseline", []string{"Test Baseline", "Approved exceptions", "Checks", "REG-001", "vendor app needs the service"}},
		{"verify", "/verify", []string{"Verify evidence", "ledger(s)", "Verified", "scans"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, s, tt.target)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200\n%s", tt.target, rec.Code, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("content type = %q, want text/html", ct)
			}
			body := rec.Body.String()
			for _, want := range tt.want {
				if !strings.Contains(body, want) {
					t.Errorf("page does not contain %q", want)
				}
			}
		})
	}
}

func TestStylesheetIsServedAsAFile(t *testing.T) {
	s, _ := testServer(t)
	rec := get(t, s, "/style.css")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /style.css = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("content type = %q, want text/css", ct)
	}
	body := rec.Body.String()
	// The report's own status styling, and the dashboard layout on top of it.
	for _, want := range []string{".badge", ".drift", ".topbar"} {
		if !strings.Contains(body, want) {
			t.Errorf("stylesheet is missing %q", want)
		}
	}
	// The pages must not need anything from the network.
	for _, forbidden := range []string{"http://", "https://", "@import", "url("} {
		if strings.Contains(body, forbidden) {
			t.Errorf("stylesheet reaches outside the binary: %q", forbidden)
		}
	}
}

// Pages must not load scripts or fonts, so the whole dashboard works on a
// machine with no network at all.
func TestPagesLoadNothingFromTheNetwork(t *testing.T) {
	s, saved := testServer(t)
	for _, target := range []string{"/", "/scans", "/scan?file=" + saved[0].File, "/compare", "/baseline", "/verify"} {
		body := get(t, s, target).Body.String()
		// No scripts, no inline styles, no frames, and nothing fetched from a
		// URL. The SVG namespace is a name, not an address, so it is left out
		// of this: nothing fetches it.
		for _, forbidden := range []string{
			"<script", "<iframe", "<object", "<embed", "@import", "<style",
			`src="http`, `href="http`, `url(http`, "//cdn", "fonts.googleapis",
		} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s contains %q", target, forbidden)
			}
		}
	}
}

func TestOnlyGETIsAllowed(t *testing.T) {
	s, _ := testServer(t)
	for _, method := range []string{
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead,
	} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, httptest.NewRequest(method, "/", nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s / = %d, want 405", method, rec.Code)
			}
			if allow := rec.Header().Get("Allow"); allow != "GET" {
				t.Errorf("Allow = %q, want GET", allow)
			}
			// A refusal still has to carry the security headers.
			if rec.Header().Get("Content-Security-Policy") == "" {
				t.Error("the 405 response has no content security policy")
			}
		})
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _ := testServer(t)
	want := map[string]string{
		"Content-Security-Policy": "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
	}
	for _, target := range []string{"/", "/scans", "/style.css", "/nope"} {
		rec := get(t, s, target)
		for header, value := range want {
			if got := rec.Header().Get(header); got != value {
				t.Errorf("%s: %s = %q, want %q", target, header, got, value)
			}
		}
	}
}

// Saved scans say where a computer is weakest, so the dashboard must never be
// reachable from the network, whatever the operator types.
func TestCheckLoopback(t *testing.T) {
	tests := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:8080", true},
		{"127.0.0.1:0", true},
		{"127.9.9.9:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{":8080", false},
		{"192.168.1.5:8080", false},
		{"10.0.0.1:8080", false},
		{"[::]:8080", false},
		{"example.com:8080", false},
		{"localhost:8080", false}, // a name can be pointed anywhere; require the IP
		{"127.0.0.1", false},      // no port
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			err := CheckLoopback(tt.addr)
			if tt.ok && err != nil {
				t.Errorf("CheckLoopback(%q) = %v, want it allowed", tt.addr, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("CheckLoopback(%q) was allowed, want it refused", tt.addr)
			}
		})
	}
}

func TestListenAndServeRefusesANonLoopbackAddress(t *testing.T) {
	s, _ := testServer(t)
	err := s.ListenAndServe("0.0.0.0:0")
	if err == nil {
		t.Fatal("ListenAndServe started on a non-loopback address")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Errorf("error = %v, want it to explain the loopback rule", err)
	}
}

// A file can only be opened through the ledger, so a crafted name cannot reach
// anything the scanner did not write.
func TestScanFileMustBeInTheLedger(t *testing.T) {
	s, saved := testServer(t)
	dir := s.dir

	// A real file in the results folder that the ledger does not list.
	unlisted := "notes.json"
	if err := os.WriteFile(filepath.Join(dir, unlisted), []byte(`{"host":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A real file outside the results folder.
	outside := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(outside, []byte(`{"host":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, file := range []string{
		"../baseline.yaml",
		"..\\baseline.yaml",
		"../../Windows/System32/drivers/etc/hosts",
		"captures/capture-LAB-WIN11.json",
		outside,
		filepath.Join(dir, saved[0].File), // the right file by full path
		unlisted,
		"chain.log",
		"",
		".",
		"..",
		strings.TrimSuffix(saved[0].File, ".json") + ".html",
	} {
		t.Run(file, func(t *testing.T) {
			rec := get(t, s, "/scan?file="+file)
			if rec.Code != http.StatusNotFound {
				t.Errorf("GET /scan?file=%s = %d, want 404", file, rec.Code)
			}
			if strings.Contains(rec.Body.String(), "secret") {
				t.Error("the response leaked a file outside the results folder")
			}
		})
	}

	// The listed name still works, so the rule is not simply refusing everything.
	if rec := get(t, s, "/scan?file="+saved[0].File); rec.Code != http.StatusOK {
		t.Errorf("GET the scan the ledger lists = %d, want 200", rec.Code)
	}
}

func TestUnknownPathIsNotFound(t *testing.T) {
	s, _ := testServer(t)
	for _, target := range []string{"/nope", "/scan/extra", "/style.css/extra"} {
		if rec := get(t, s, target); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
		}
	}
}

// A path with dot segments is cleaned and redirected by the router before any
// handler sees it, and the cleaned path stays on this server.
func TestDotSegmentsAreCleanedAway(t *testing.T) {
	s, _ := testServer(t)
	rec := get(t, s, "/../etc")
	if rec.Code == http.StatusOK {
		t.Fatalf("GET /../etc = 200, want a redirect or a refusal")
	}
	if location := rec.Header().Get("Location"); location != "" && !strings.HasPrefix(location, "/") {
		t.Errorf("redirected off this server, to %q", location)
	}
}

func TestScanFilters(t *testing.T) {
	s, saved := testServer(t)
	newest := saved[len(saved)-1].File

	tests := []struct {
		name       string
		query      string
		wantShown  []string
		wantHidden []string
	}{
		{"no filter shows both", "", []string{"REG-001", "SVC-001"}, nil},
		{"by status", "&status=DRIFT", []string{"SVC-001"}, []string{"REG-001"}},
		{"by severity", "&severity=high", []string{"REG-001"}, []string{"SVC-001"}},
		{"by check type", "&type=service", []string{"SVC-001"}, []string{"REG-001"}},
		{"status and severity together", "&status=DRIFT&severity=high", nil, []string{"REG-001", "SVC-001"}},
		{"an unknown value is ignored", "&status=BOGUS", []string{"REG-001", "SVC-001"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := get(t, s, "/scan?file="+newest+tt.query).Body.String()
			rows := body[strings.Index(body, "<tbody>"):]
			for _, want := range tt.wantShown {
				if !strings.Contains(rows, want) {
					t.Errorf("filtered table does not show %s", want)
				}
			}
			for _, hidden := range tt.wantHidden {
				if strings.Contains(rows, hidden) {
					t.Errorf("filtered table still shows %s", hidden)
				}
			}
		})
	}
}

// The baseline page has to make a lapsed approval obvious, and warn before one
// lapses, since an exception nobody reviews is just undocumented drift.
func TestBaselinePageMarksExpiringExceptions(t *testing.T) {
	s, _ := testServer(t)
	body := get(t, s, "/baseline").Body.String()
	for _, want := range []string{"EXPIRED", "EXPIRES IN 12 DAYS"} {
		if !strings.Contains(body, want) {
			t.Errorf("baseline page is missing %q", want)
		}
	}
}

func TestOverviewWithoutAnyScans(t *testing.T) {
	s := New(Options{Dir: t.TempDir(), Now: func() time.Time { return testNow }})
	rec := get(t, s, "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	// This computer is always listed, so an empty folder says what is missing
	// rather than showing nothing at all.
	for _, want := range []string{"NEVER SCANNED", "No evidence has been saved for this computer yet"} {
		if !strings.Contains(body, want) {
			t.Errorf("an empty results folder should say %q", want)
		}
	}
}

// A computer with no capture still gets a useful list: what the previous scan
// did not find.
func TestOverviewFallsBackToNewSinceLastScan(t *testing.T) {
	dir := t.TempDir()
	for i, drift := range []bool{false, true} {
		s := report.Scan{
			Host:      "LAB-WIN11",
			StartedAt: testNow.Add(time.Duration(i) * time.Hour),
			Results:   results(drift, ""),
		}
		s.Summary = report.Summarize(s.Results)
		if _, err := report.Save(dir, s); err != nil {
			t.Fatal(err)
		}
	}
	body := get(t, New(Options{Dir: dir, Now: func() time.Time { return testNow }}), "/scans").Body.String()
	if !strings.Contains(body, "New since the previous scan") {
		t.Error("a scan with no capture should fall back to comparing with the previous scan")
	}
	if !strings.Contains(body, "SVC-001") {
		t.Error("the newly drifting check should be listed")
	}
	if strings.Contains(body, "Changed since the approved capture") {
		t.Error("a computer with no capture should not claim to have one")
	}
}

// A file that no longer matches its ledger hash is still shown, but it is
// labeled, so nobody reads a tampered scan as evidence.
func TestEditedScanIsLabeledUnverified(t *testing.T) {
	s, saved := testServer(t)
	path := filepath.Join(s.dir, saved[len(saved)-1].File)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), `"drift": 1`, `"drift": 0`, 1)
	if edited == string(data) {
		t.Fatal("test setup: the drift count was not found in the saved scan")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	if body := get(t, s, "/").Body.String(); !strings.Contains(body, "UNVERIFIED") {
		t.Error("the overview should flag a computer whose latest scan does not match the ledger")
	}
	if body := get(t, s, "/scans").Body.String(); !strings.Contains(body, "UNVERIFIED") {
		t.Error("the scans list should flag it too")
	}
	if body := get(t, s, "/verify").Body.String(); !strings.Contains(body, "Chain broken") {
		t.Error("the verify page should report the broken chain")
	}
}
