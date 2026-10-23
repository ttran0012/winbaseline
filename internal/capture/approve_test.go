package capture

import (
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

var approvedAt = time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)

func res(id, status, normalized string) compare.Result {
	return compare.Result{ID: id, Title: id, Severity: "high", Status: status, Normalized: normalized}
}

func scanOf(results ...compare.Result) report.Scan {
	return report.Scan{
		Host:            "WS02",
		BaselineName:    "Test Baseline",
		BaselineVersion: "9.9.9",
		StartedAt:       approvedAt.Add(-time.Hour),
		Results:         results,
		Summary:         report.Summarize(results),
	}
}

func approveOpts() ApproveOptions {
	return ApproveOptions{
		ApprovedBy: `LAB\itadmin`,
		At:         approvedAt,
		Note:       "reviewed after the October rebuild",
		SourceFile: "scan-WS02-20261023-080000-000.json",
		SourceHash: strings.Repeat("a", 64),
	}
}

// A capture built from a scan records the normalized value of each check, so a
// later scan can be measured against it exactly as one built by -capture.
func TestFromScanBuildsEntriesFromNormalizedValues(t *testing.T) {
	s := scanOf(
		res("REG-001", compare.Compliant, "1"),
		res("SVC-001", compare.Drift, "manual"),
		res("GRP-001", compare.Exception, "PC\\Administrator, PC\\vendor"),
	)
	c, err := FromScan(s, approveOpts())
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != "WS02" || c.BaselineVersion != "9.9.9" {
		t.Errorf("capture = %+v", c)
	}
	if c.Approval == nil {
		t.Fatal("the capture records no approval")
	}
	a := c.Approval
	if a.ApprovedBy != `LAB\itadmin` || a.Note != "reviewed after the October rebuild" {
		t.Errorf("approval = %+v", a)
	}
	if a.SourceScan != "scan-WS02-20261023-080000-000.json" || a.SourceHash != strings.Repeat("a", 64) {
		t.Errorf("approval does not name the source scan: %+v", a)
	}
	if !a.ApprovedAt.Equal(approvedAt) || !c.CapturedAt.Equal(approvedAt) {
		t.Errorf("approval time = %v / %v, want %v", a.ApprovedAt, c.CapturedAt, approvedAt)
	}

	want := map[string]string{"REG-001": "1", "SVC-001": "manual", "GRP-001": "PC\\Administrator, PC\\vendor"}
	got := c.Values()
	if len(got) != len(want) {
		t.Fatalf("recorded %d entries, want %d", len(got), len(want))
	}
	for id, value := range want {
		if got[id] != value {
			t.Errorf("entry %s = %q, want %q", id, got[id], value)
		}
	}
	// The drift is approved as-is, so a later identical scan is UNCHANGED.
	if drifting := c.Drifting(); len(drifting) != 1 || drifting[0] != "SVC-001" {
		t.Errorf("Drifting() = %v, want [SVC-001]", drifting)
	}
}

// "unreadable" must never be recorded as the approved configuration, so an
// unreadable check is refused unless it is explicitly left out, and then it is
// listed as excluded rather than stored as a value.
func TestFromScanHandlesUnreadableChecks(t *testing.T) {
	s := scanOf(
		res("REG-001", compare.Compliant, "1"),
		res("AUD-001", compare.Error, "unreadable"),
		res("AUD-002", compare.Error, "unreadable"),
	)

	if _, err := FromScan(s, approveOpts()); err == nil {
		t.Fatal("approving a scan with unreadable checks should be refused without exclusion")
	} else if !strings.Contains(err.Error(), "AUD-001") || !strings.Contains(err.Error(), "AUD-002") {
		t.Errorf("the refusal should name the unreadable checks, got %q", err)
	}

	o := approveOpts()
	o.ExcludeErrors = true
	c, err := FromScan(s, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Values()["AUD-001"]; ok {
		t.Error("an unreadable check was recorded as a value")
	}
	if len(c.Approval.ExcludedChecks) != 2 {
		t.Errorf("excluded = %v, want the two unreadable checks", c.Approval.ExcludedChecks)
	}
	if len(c.Entries) != 1 || c.Entries[0].ID != "REG-001" {
		t.Errorf("entries = %+v, want only REG-001", c.Entries)
	}
}

func TestFromScanRefusesEmptyNote(t *testing.T) {
	o := approveOpts()
	o.Note = ""
	if _, err := FromScan(scanOf(res("REG-001", compare.Compliant, "1")), o); err != ErrReviewRequired {
		t.Errorf("FromScan with no note = %v, want ErrReviewRequired", err)
	}
}

// A scan saved before normalized values existed cannot be approved: there is
// nothing to record as the configuration.
func TestFromScanRefusesAScanWithoutNormalizedValues(t *testing.T) {
	s := scanOf(compare.Result{ID: "REG-001", Status: compare.Compliant}) // no Normalized
	if _, err := FromScan(s, approveOpts()); err == nil || !strings.Contains(err.Error(), "re-scan") {
		t.Errorf("FromScan = %v, want it to refuse a pre-feature scan", err)
	}
}

func TestFromScanRefusesWhenEverythingIsUnreadable(t *testing.T) {
	o := approveOpts()
	o.ExcludeErrors = true
	s := scanOf(res("AUD-001", compare.Error, "unreadable"))
	if _, err := FromScan(s, o); err == nil || !strings.Contains(err.Error(), "nothing readable") {
		t.Errorf("FromScan = %v, want it to refuse when nothing can be approved", err)
	}
}
