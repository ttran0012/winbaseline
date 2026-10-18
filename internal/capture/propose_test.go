package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/compare"
)

// draftCapture holds one check of every status, so only the drifting ones
// should turn into proposed exceptions.
func draftCapture() *Capture {
	return &Capture{
		Host:       "LAB-WIN11",
		CapturedAt: capturedAt,
		CapturedBy: `LAB-WIN11\itadmin`,
		Entries: []Entry{
			{ID: "REG-001", Value: "1", Status: compare.Compliant},
			{ID: "REG-002", Value: "0", Status: compare.Drift},
			{ID: "AUD-001", Value: "unreadable", Status: compare.Error},
			{ID: "SW-002", Value: "AnyDesk", Status: compare.Exception},
			{ID: "SVC-001", Value: "manual", Status: compare.Drift},
		},
	}
}

// parseDraft reads the generated YAML back as an exceptions list.
func parseDraft(t *testing.T, data []byte) []baseline.Exception {
	t.Helper()
	var draft struct {
		Exceptions []baseline.Exception `yaml:"exceptions"`
	}
	if err := yaml.Unmarshal(data, &draft); err != nil {
		t.Fatalf("the draft is not valid YAML: %v\n%s", err, data)
	}
	return draft.Exceptions
}

func TestProposeExceptions(t *testing.T) {
	c := draftCapture()
	expires := capturedAt.AddDate(0, 0, ProposedExceptionDays)
	data, err := ProposeExceptions(c, expires)
	if err != nil {
		t.Fatal(err)
	}
	got := parseDraft(t, data)

	want := []baseline.Exception{
		{Check: "REG-002", Hosts: []string{"LAB-WIN11"}, Reason: "TODO", ApprovedBy: "TODO", Expires: "2027-01-16"},
		{Check: "SVC-001", Hosts: []string{"LAB-WIN11"}, Reason: "TODO", ApprovedBy: "TODO", Expires: "2027-01-16"},
	}
	if len(got) != len(want) {
		t.Fatalf("proposed %d exceptions, want %d:\n%s", len(got), len(want), data)
	}
	for i, w := range want {
		if got[i].Check != w.Check || got[i].Reason != w.Reason || got[i].ApprovedBy != w.ApprovedBy || got[i].Expires != w.Expires {
			t.Errorf("exception %d = %+v, want %+v", i, got[i], w)
		}
		if len(got[i].Hosts) != 1 || got[i].Hosts[0] != "LAB-WIN11" {
			t.Errorf("exception %d hosts = %v, want [LAB-WIN11]", i, got[i].Hosts)
		}
	}

	// 90 days is far enough to be useful and near enough to come back for review.
	if days := expires.Sub(capturedAt).Hours() / 24; days != 90 {
		t.Errorf("drafted expiry is %v days out, want 90", days)
	}
	// The header has to say what to do with the file, since nothing else will.
	for _, want := range []string{"# Draft exceptions for LAB-WIN11", "TODO", "baseline is never edited for you"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the draft does not explain itself: missing %q", want)
		}
	}
}

func TestProposeExceptionsWithNothingDrifting(t *testing.T) {
	c := draftCapture()
	for i := range c.Entries {
		c.Entries[i].Status = compare.Compliant
	}
	data, err := ProposeExceptions(c, capturedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseDraft(t, data); len(got) != 0 {
		t.Errorf("proposed %d exceptions for a clean computer", len(got))
	}
}

// The whole point of the placeholders: a draft is pasted into the baseline by a
// person, and the baseline refuses to load until that person has filled in why
// the deviation is acceptable and who accepted it.
func TestProposedExceptionsDoNotLoadUntilFilledIn(t *testing.T) {
	data, err := ProposeExceptions(draftCapture(), capturedAt.AddDate(0, 0, ProposedExceptionDays))
	if err != nil {
		t.Fatal(err)
	}

	b := baseline.Baseline{
		Name: "test",
		Checks: []baseline.Check{
			{ID: "REG-002", Severity: "low", Type: baseline.TypeService, Service: "upnphost", Expected: "disabled"},
			{ID: "SVC-001", Severity: "low", Type: baseline.TypeService, Service: "sshd", Expected: "disabled"},
		},
	}
	if err := yaml.Unmarshal(data, &b); err != nil {
		t.Fatalf("the draft does not paste into a baseline: %v", err)
	}
	if len(b.Exceptions) != 2 {
		t.Fatalf("pasted %d exceptions, want 2", len(b.Exceptions))
	}

	err = b.Validate()
	if err == nil || !strings.Contains(err.Error(), "TODO") {
		t.Fatalf("Validate() = %v, want it to refuse the placeholders", err)
	}

	for i := range b.Exceptions {
		b.Exceptions[i].Reason = "vendor app needs it until the 2027 replacement"
		b.Exceptions[i].ApprovedBy = "J. Lee, IT Manager"
	}
	if err := b.Validate(); err != nil {
		t.Errorf("Validate() = %v, want the filled-in draft to be accepted", err)
	}
}

func TestSaveProposedExceptions(t *testing.T) {
	dir := t.TempDir()
	c := draftCapture()
	expires := capturedAt.AddDate(0, 0, ProposedExceptionDays)

	path, err := SaveProposedExceptions(dir, c, expires)
	if err != nil {
		t.Fatal(err)
	}
	if base := filepath.Base(path); !strings.HasPrefix(base, "proposed-exceptions-LAB-WIN11-") || !strings.HasSuffix(base, ".yaml") {
		t.Errorf("draft file is named %s", base)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseDraft(t, data); len(got) != 2 {
		t.Errorf("the saved draft holds %d exceptions, want 2", len(got))
	}

	// A draft is not evidence, so it stays out of the capture chain.
	if _, err := os.Stat(filepath.Join(dir, "chain.log")); err == nil {
		t.Error("writing a draft should not start a chain")
	}
	if _, err := SaveProposedExceptions(dir, c, expires); err == nil {
		t.Error("a second draft with the same name should be refused")
	}
}
