package serve

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hostList writes an approved host list naming one computer, and returns its path.
func hostList(t *testing.T, dir, host, expires string) string {
	t.Helper()
	path := filepath.Join(dir, "hosts.yaml")
	file := "authorization:\n" +
		"  approved_by: \"J. Lee, IT Manager\"\n" +
		"  approved: \"2026-10-01\"\n" +
		"  expires: \"" + expires + "\"\n" +
		"  scope: \"quarterly CIS review\"\n" +
		"hosts:\n" +
		"  - name: " + host + "\n" +
		"    label: \"test server\"\n"
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// post sends a form to the scan endpoint the way a browser would.
func post(t *testing.T, s *Server, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, startScanPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "http://"+r.Host)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	for k, v := range headers {
		if v == "" {
			r.Header.Del(k)
			continue
		}
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec
}

// Starting a scan is the one thing the dashboard does that is not reading, so
// it only happens for a form this server rendered.
func TestStartScanNeedsATrustedForm(t *testing.T) {
	s, _ := testServer(t)

	tests := []struct {
		name    string
		form    url.Values
		headers map[string]string
		want    int
	}{
		{"no token at all", url.Values{"target": {""}}, nil, http.StatusForbidden},
		{"a wrong token", url.Values{"target": {""}, "csrf": {"not-the-token"}}, nil, http.StatusForbidden},
		{"an empty token", url.Values{"target": {""}, "csrf": {""}}, nil, http.StatusForbidden},
		{"the right token from another site", url.Values{"target": {""}, "csrf": {s.csrf}},
			map[string]string{"Origin": "http://evil.example", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"a foreign origin even if the fetch claims same-origin", url.Values{"target": {""}, "csrf": {s.csrf}},
			map[string]string{"Origin": "http://evil.example"}, http.StatusForbidden},
		{"a cross-site fetch even with no origin", url.Values{"target": {""}, "csrf": {s.csrf}},
			map[string]string{"Origin": "", "Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"a same-site fetch, which is another port on this machine", url.Values{"target": {""}, "csrf": {s.csrf}},
			map[string]string{"Origin": "", "Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := post(t, s, tt.form, tt.headers)
			if rec.Code != tt.want {
				t.Errorf("POST = %d, want %d: %s", rec.Code, tt.want, rec.Body.String())
			}
			if s.runner.running() {
				t.Error("a refused request started a scan anyway")
			}
		})
	}
}

// What a real browser sends. These pages set Referrer-Policy: no-referrer, and
// the Fetch standard says a form posted from such a page carries Origin: null,
// so refusing a literal "null" origin refused every click on the button. The
// token and Sec-Fetch-Site are what place the request.
func TestStartScanAcceptsTheFormABrowserActuallySends(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.yaml")
	if err := os.WriteFile(baselinePath, []byte(testBaseline), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Options{Dir: dir, BaselinePath: baselinePath, Now: time.Now})

	rec := post(t, s, url.Values{"target": {""}, "csrf": {s.csrf}}, map[string]string{
		"Origin":         "null",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	waitForScan(t, s)

	// The same request without the token is still refused.
	again := post(t, s, url.Values{"target": {""}}, map[string]string{
		"Origin":         "null",
		"Sec-Fetch-Site": "same-origin",
	})
	if again.Code != http.StatusForbidden {
		t.Errorf("POST with no token = %d, want 403", again.Code)
	}
}

// waitForScan waits for the running scan to finish.
func waitForScan(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for s.runner.running() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.runner.running() {
		t.Fatal("the scan did not finish in time")
	}
}

// A dashboard that scans whatever it is told to is a different and much worse
// tool, so a computer has to be named in the approved list.
func TestStartScanOnlyScansApprovedComputers(t *testing.T) {
	s, _ := testServer(t)
	s.hostsPath = hostList(t, s.dir, "SQL-02", "2026-12-31")

	for _, target := range []string{
		"SQL-99",        // not in the list
		"10.0.0.5",      // an address, which the list format refuses
		"SQL-*",         // a wildcard
		`\\SQL-02`,      // a UNC path
		"../../SQL-02",  // a path
		"SQL-02 SQL-99", // two at once
		"localhost",     // not listed either
	} {
		t.Run(target, func(t *testing.T) {
			rec := post(t, s, url.Values{"target": {target}, "csrf": {s.csrf}}, nil)
			if rec.Code != http.StatusForbidden {
				t.Errorf("POST target=%s = %d, want 403: %s", target, rec.Code, rec.Body.String())
			}
			if s.runner.running() {
				t.Errorf("a scan of %s was started", target)
			}
		})
	}
}

// An approval with a date on it is only an approval while the date holds.
func TestStartScanRefusesAnExpiredApproval(t *testing.T) {
	s, _ := testServer(t)
	s.hostsPath = hostList(t, s.dir, "SQL-02", "2026-10-01") // testNow is later

	rec := post(t, s, url.Values{"target": {"SQL-02"}, "csrf": {s.csrf}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("the refusal should say the approval expired, got %q", rec.Body.String())
	}
}

// Without a host list the dashboard can still scan the computer it runs on, and
// nothing else.
func TestStartScanWithoutAHostListOffersOnlyThisComputer(t *testing.T) {
	s, _ := testServer(t)
	s.hostsPath = ""

	body := get(t, s, "/").Body.String()
	if !strings.Contains(body, "Only this computer can be scanned") {
		t.Error("the overview should say that only this computer can be scanned")
	}
	rec := post(t, s, url.Values{"target": {"SQL-02"}, "csrf": {s.csrf}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST target=SQL-02 = %d, want 403", rec.Code)
	}
}

// Reloading the page must not read every server in the building twice.
func TestOnlyOneScanRunsAtATime(t *testing.T) {
	var r runner
	release := make(chan struct{})
	started := make(chan struct{})

	first, err := r.start([]string{"SQL-02"}, testNow, func(rec *recorder) {
		rec.reading("SQL-02")
		close(started)
		<-release
		rec.done(jobResult{Host: "SQL-02", Code: 1})
	})
	if err != nil {
		t.Fatal(err)
	}
	<-started

	if _, err := r.start([]string{"DC-01"}, testNow, func(*recorder) {
		t.Error("a second job ran while the first was still going")
	}); err == nil {
		t.Fatal("a second scan was allowed to start")
	}

	j, running := r.state()
	if !running || j.Current != "SQL-02" || j.Progress() != "0 of 1" {
		t.Errorf("state while running = %+v, running = %v", j, running)
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for r.running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.running() {
		t.Fatal("the job never finished")
	}

	done, running := r.state()
	switch {
	case running:
		t.Error("still reported as running")
	case !done.Done:
		t.Error("the finished job is not marked done")
	case done.Progress() != "1 of 1":
		t.Errorf("progress = %s, want 1 of 1", done.Progress())
	case done.Worst() != 1:
		t.Errorf("worst = %d, want 1", done.Worst())
	case done.ID != first.ID:
		t.Errorf("the finished job is %s, want %s", done.ID, first.ID)
	}
}

// A panic while reading one computer must not take the dashboard down, or leave
// it looking busy forever.
func TestARunawayScanDoesNotWedgeTheRunner(t *testing.T) {
	var r runner
	if _, err := r.start([]string{"SQL-02"}, testNow, func(*recorder) {
		panic("the collector exploded")
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.running() {
		t.Fatal("the runner is still busy after the job panicked")
	}
	j, _ := r.state()
	if j == nil || !strings.Contains(j.Err, "stopped unexpectedly") {
		t.Errorf("the job should record that it stopped: %+v", j)
	}
}

func TestJobPageBeforeAnyScan(t *testing.T) {
	s, _ := testServer(t)
	rec := get(t, s, "/job")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /job = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No scan has been started") {
		t.Error("the job page should say that nothing has run yet")
	}
}

// The job page reports progress without any script, which means it refreshes
// itself while a scan is running and stops once it is done.
func TestJobPageRefreshesOnlyWhileRunning(t *testing.T) {
	s, _ := testServer(t)
	release := make(chan struct{})
	if _, err := s.runner.start([]string{"SQL-02"}, testNow, func(rec *recorder) {
		rec.reading("SQL-02")
		<-release
		rec.done(jobResult{Host: "SQL-02", Code: 0})
	}); err != nil {
		t.Fatal(err)
	}

	body := get(t, s, "/job").Body.String()
	if !strings.Contains(body, `http-equiv="refresh"`) {
		t.Error("the job page should refresh itself while a scan is running")
	}
	for _, want := range []string{"Running", "SQL-02", "0 of 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("the running job page is missing %q", want)
		}
	}
	// The overview says so too, instead of offering to start another.
	if overview := get(t, s, "/").Body.String(); !strings.Contains(overview, "A scan is running now") {
		t.Error("the overview should say a scan is running")
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for s.runner.running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	done := get(t, s, "/job").Body.String()
	if strings.Contains(done, `http-equiv="refresh"`) {
		t.Error("the job page should stop refreshing once the scan has finished")
	}
	if !strings.Contains(done, "Finished") {
		t.Error("the finished job page should say so")
	}
}

// The whole point of the button: it really does run a scan and save evidence
// that verifies, in the same chain a command-line scan would use.
func TestStartScanOfThisComputerSavesVerifiableEvidence(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.yaml")
	if err := os.WriteFile(baselinePath, []byte(testBaseline), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Options{Dir: dir, BaselinePath: baselinePath, Now: time.Now})

	rec := post(t, s, url.Values{"target": {""}, "csrf": {s.csrf}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	if location := rec.Header().Get("Location"); location != "/job" {
		t.Errorf("redirected to %q, want /job", location)
	}

	waitForScan(t, s)

	j, _ := s.runner.state()
	if j == nil || len(j.Results) != 1 {
		t.Fatalf("job = %+v, want one result", j)
	}
	if j.Err != "" {
		t.Fatalf("the job reported %q", j.Err)
	}
	res := j.Results[0]
	if res.Err != "" {
		t.Fatalf("the scan was not saved: %s", res.Err)
	}
	if res.Summary.Total != 2 {
		t.Errorf("checked %d settings, want the 2 in the test baseline", res.Summary.Total)
	}

	// The evidence it wrote is real evidence: it is in the chain and verifies.
	if chain := s.verifyChains(); !chain.OK() || chain.Records != 1 {
		t.Fatalf("verify = %+v; want the one scan to verify", chain)
	}
	if body := get(t, s, "/job").Body.String(); !strings.Contains(body, res.File) {
		t.Error("the job page should name the evidence file it saved")
	}
	if body := get(t, s, "/scans").Body.String(); !strings.Contains(body, res.File) {
		t.Error("the new scan should appear in the scans list")
	}
}
