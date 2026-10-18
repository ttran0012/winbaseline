package capture

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

var capturedAt = time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC)

// stub reads the values a test hands it instead of the local system.
type stub map[string]collect.Reading

func (s stub) Read(chk baseline.Check) collect.Reading { return s[chk.ID] }

// testBaseline has one check that is compliant and two that are not, so the
// capture records a mix of statuses.
func testBaseline() *baseline.Baseline {
	reg := func(id, expected string) baseline.Check {
		return baseline.Check{ID: id, Severity: "high", Type: baseline.TypeRegistry,
			Hive: "HKLM", Path: `A\B`, Value: "V", Operator: "equals", Expected: expected}
	}
	return &baseline.Baseline{
		Name:    "Test Baseline",
		Version: "9.9.9",
		Checks: []baseline.Check{
			reg("REG-001", "1"),
			reg("REG-002", "1"),
			{ID: "SVC-001", Severity: "low", Type: baseline.TypeService, Service: "upnphost", Expected: "disabled"},
		},
	}
}

func testOptions() Options {
	return Options{Host: "LAB-WIN11", CapturedBy: `LAB-WIN11\itadmin`, At: capturedAt, Elevated: true}
}

func testReadings() stub {
	return stub{
		"REG-001": {Present: true, Num: 1},
		"REG-002": {Present: true, Num: 0},
		"SVC-001": {Present: true, Num: 3, Text: "manual"},
	}
}

// Capturing without administrator rights would record the audit policy as
// unreadable and treat that as this computer's approved configuration.
func TestRecordRefusesWithoutAdministrator(t *testing.T) {
	o := testOptions()
	o.Elevated = false
	c, err := Record(testBaseline(), testReadings(), o)
	if !errors.Is(err, ErrNotElevated) {
		t.Fatalf("Record() error = %v, want ErrNotElevated", err)
	}
	if c != nil {
		t.Error("Record returned a capture it refused to take")
	}
	if !strings.Contains(err.Error(), "administrator") {
		t.Errorf("the refusal should say what is wrong, got %q", err)
	}
}

func TestRecord(t *testing.T) {
	c, err := Record(testBaseline(), testReadings(), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "LAB-WIN11" || c.CapturedBy != `LAB-WIN11\itadmin` || !c.CapturedAt.Equal(capturedAt) {
		t.Errorf("capture records %s by %s at %s", c.Host, c.CapturedBy, c.CapturedAt)
	}
	if c.BaselineName != "Test Baseline" || c.BaselineVersion != "9.9.9" {
		t.Errorf("capture records baseline %s v%s", c.BaselineName, c.BaselineVersion)
	}

	want := []Entry{
		{ID: "REG-001", Value: "1", Status: compare.Compliant},
		{ID: "REG-002", Value: "0", Status: compare.Drift},
		{ID: "SVC-001", Value: "manual", Status: compare.Drift},
	}
	if len(c.Entries) != len(want) {
		t.Fatalf("captured %d entries, want %d", len(c.Entries), len(want))
	}
	for i, w := range want {
		if c.Entries[i] != w {
			t.Errorf("entry %d = %+v, want %+v", i, c.Entries[i], w)
		}
	}
	if got := c.Values()["SVC-001"]; got != "manual" {
		t.Errorf("Values()[SVC-001] = %q, want manual", got)
	}
	if got := c.Drifting(); len(got) != 2 || got[0] != "REG-002" || got[1] != "SVC-001" {
		t.Errorf("Drifting() = %v, want [REG-002 SVC-001]", got)
	}
}

// A deviation the organization has already approved is recorded as an exception
// and is not offered for approval again.
func TestRecordAppliesApprovedExceptions(t *testing.T) {
	b := testBaseline()
	b.Exceptions = []baseline.Exception{{
		Check:      "SVC-001",
		Reason:     "vendor app needs the service",
		ApprovedBy: "J. Lee",
		Expires:    "2026-12-31",
	}}
	c, err := Record(b, testReadings(), testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Entries[2]; got.Status != compare.Exception {
		t.Errorf("SVC-001 status = %s, want %s", got.Status, compare.Exception)
	}
	if got := c.Drifting(); len(got) != 1 || got[0] != "REG-002" {
		t.Errorf("Drifting() = %v, want only [REG-002]", got)
	}
}

func saveCapture(t *testing.T, dir, host string, at time.Time, value string) report.ChainEntry {
	t.Helper()
	entry, err := Save(dir, &Capture{
		Host:       host,
		CapturedAt: at,
		CapturedBy: `LAB-WIN11\itadmin`,
		Entries:    []Entry{{ID: "REG-001", Value: value, Status: compare.Compliant}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestCaptureChainVerifiesAndDetectsEdits(t *testing.T) {
	dir := t.TempDir()
	saveCapture(t, dir, "LAB-WIN11", capturedAt, "1")
	second := saveCapture(t, dir, "LAB-WIN11", capturedAt.Add(time.Hour), "1")

	if n, err := report.Verify(dir); err != nil || n != 2 {
		t.Fatalf("Verify = %d, %v; want 2, nil", n, err)
	}

	path := filepath.Join(dir, second.File)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), `"value": "1"`, `"value": "0"`, 1)
	if edited == string(data) {
		t.Fatal("test setup: the captured value was not found in the saved file")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := report.Verify(dir); err == nil || !strings.Contains(err.Error(), "modified") {
		t.Errorf("Verify should report the edited capture, got %v", err)
	}
	// A scan must not quietly compare against a capture that was edited.
	if _, err := Latest(dir, "LAB-WIN11"); err == nil || !strings.Contains(err.Error(), "modified") {
		t.Errorf("Latest should refuse the edited capture, got %v", err)
	}
}

func TestSaveNeverOverwritesACapture(t *testing.T) {
	dir := t.TempDir()
	saveCapture(t, dir, "LAB-WIN11", capturedAt, "1")
	if _, err := Save(dir, &Capture{Host: "LAB-WIN11", CapturedAt: capturedAt}); err == nil {
		t.Error("a second capture with the same name should be refused")
	}
	if n, err := report.Verify(dir); err != nil || n != 1 {
		t.Fatalf("the chain should still verify with 1 capture, got %d, %v", n, err)
	}
}

func TestLatest(t *testing.T) {
	dir := t.TempDir()
	if got, err := Latest(dir, "LAB-WIN11"); err != nil || got != nil {
		t.Fatalf("Latest in an empty folder = %v, %v; want nil, nil", got, err)
	}

	saveCapture(t, dir, "LAB-WIN11", capturedAt, "old")
	saveCapture(t, dir, "LAB-WIN10", capturedAt.Add(time.Hour), "other host")
	newest := saveCapture(t, dir, "LAB-WIN11", capturedAt.Add(2*time.Hour), "newest")
	saveCapture(t, dir, "LAB-WIN10", capturedAt.Add(3*time.Hour), "other host")

	got, err := Latest(dir, "LAB-WIN11")
	if err != nil {
		t.Fatal(err)
	}
	if got.File != newest.File || got.Hash != newest.Hash {
		t.Errorf("Latest = %s (%s), want %s (%s)", got.File, got.Hash, newest.File, newest.Hash)
	}
	if v := got.Capture.Values()["REG-001"]; v != "newest" {
		t.Errorf("Latest returned the capture holding %q", v)
	}

	// Windows treats computer names case-insensitively, so the lookup does too.
	if same, err := Latest(dir, "lab-win11"); err != nil || same == nil || same.File != newest.File {
		t.Errorf("Latest(lab-win11) = %v, %v; want the same capture", same, err)
	}
	if none, err := Latest(dir, "LAB-WIN7"); err != nil || none != nil {
		t.Errorf("Latest for a host with no capture = %v, %v; want nil, nil", none, err)
	}
}

// editCapture rewrites one saved capture file, leaving the ledger alone.
func editCapture(t *testing.T, dir, file, from, to string) {
	t.Helper()
	path := filepath.Join(dir, file)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(data), from, to, 1)
	if edited == string(data) {
		t.Fatalf("test setup: %q is not in %s", from, file)
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Editing the host of the newest capture used to be enough to get past it: the
// host was read before the hash was checked, so the walk skipped the file it
// had not verified and treated an older capture as the approved one. The hash
// now has to clear first, so the folder is rejected instead.
func TestLatestRefusesWhenTheNewestCaptureHostWasEdited(t *testing.T) {
	dir := t.TempDir()
	saveCapture(t, dir, "LAB-WIN11", capturedAt, "old")
	newest := saveCapture(t, dir, "LAB-WIN11", capturedAt.Add(time.Hour), "newest")
	editCapture(t, dir, newest.File, `"host": "LAB-WIN11"`, `"host": "OTHER-PC"`)

	got, err := Latest(dir, "LAB-WIN11")
	if err == nil {
		t.Fatal("Latest accepted a capture folder holding an edited capture")
	}
	if got != nil {
		t.Fatalf("Latest fell back to %s instead of refusing the folder", got.File)
	}
	if !strings.Contains(err.Error(), "modified") {
		t.Errorf("the refusal should say the record was modified, got %q", err)
	}
}

// The same goes for an edit anywhere else in the folder: a ledger that no
// longer vouches for every capture vouches for none of them.
func TestLatestRefusesWhenAnOlderCaptureWasEdited(t *testing.T) {
	dir := t.TempDir()
	oldest := saveCapture(t, dir, "LAB-WIN11", capturedAt, "old")
	saveCapture(t, dir, "LAB-WIN11", capturedAt.Add(time.Hour), "newest")
	editCapture(t, dir, oldest.File, `"value": "old"`, `"value": "doctored"`)

	got, err := Latest(dir, "LAB-WIN11")
	if err == nil || got != nil {
		t.Fatalf("Latest = %v, %v; want it to refuse the folder", got, err)
	}
}

func TestLatestRefusesWhenACaptureIsMissing(t *testing.T) {
	dir := t.TempDir()
	gone := saveCapture(t, dir, "LAB-WIN11", capturedAt, "old")
	saveCapture(t, dir, "LAB-WIN11", capturedAt.Add(time.Hour), "newest")
	if err := os.Remove(filepath.Join(dir, gone.File)); err != nil {
		t.Fatal(err)
	}

	got, err := Latest(dir, "LAB-WIN11")
	if err == nil || got != nil {
		t.Fatalf("Latest = %v, %v; want it to refuse the folder", got, err)
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("the refusal should say a record is missing, got %q", err)
	}
}

// A folder nobody has captured into is not a failure; those scans simply report
// no change at all.
func TestLatestAcceptsAFolderWithNoCaptures(t *testing.T) {
	if got, err := Latest(t.TempDir(), "LAB-WIN11"); got != nil || err != nil {
		t.Fatalf("Latest = %v, %v; want nil, nil", got, err)
	}
}
