package serve

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// res builds one result for the comparison tests.
func res(id, status, actual string) compare.Result {
	return compare.Result{ID: id, Title: id + " setting", Severity: "high", Status: status, Actual: actual}
}

func scanOf(rs ...compare.Result) report.Scan {
	return report.Scan{Results: rs, Summary: report.Summarize(rs)}
}

// groupOf finds which group a check landed in, so each case can name one.
func groupOf(c comparison, id string) string {
	for _, g := range c.Groups() {
		for _, d := range g.Rows {
			if d.ID == id {
				return g.Title
			}
		}
	}
	return "none"
}

func TestCompareScansGrouping(t *testing.T) {
	tests := []struct {
		name  string
		from  compare.Result
		to    compare.Result
		want  string
		notes string
	}{
		{"started drifting", res("C-1", compare.Compliant, "1"), res("C-1", compare.Drift, "0"), "New drift", ""},
		{"stopped drifting", res("C-1", compare.Drift, "0"), res("C-1", compare.Compliant, "1"), "Fixed", ""},
		{"drifting throughout", res("C-1", compare.Drift, "0"), res("C-1", compare.Drift, "0"), "Still drifting", ""},
		{"drifting, and the value moved again", res("C-1", compare.Drift, "0"), res("C-1", compare.Drift, "2"), "Still drifting", ""},
		{"same value, same status", res("C-1", compare.Compliant, "1"), res("C-1", compare.Compliant, "1"), "none", ""},
		{"value moved while still compliant", res("C-1", compare.Compliant, "1"), res("C-1", compare.Compliant, "3"), "Changed values", ""},

		// An approved exception is a deviation someone signed for, not a fix.
		{"approved in between", res("C-1", compare.Drift, "0"), res("C-1", compare.Exception, "0"), "Still drifting", ""},
		{"approval lapsed", res("C-1", compare.Exception, "0"), res("C-1", compare.Drift, "0"), "Still drifting", ""},
		{"approval lapsed after the setting was corrected", res("C-1", compare.Exception, "0"), res("C-1", compare.Compliant, "1"), "Fixed", ""},
		{"newly approved deviation", res("C-1", compare.Compliant, "1"), res("C-1", compare.Exception, "0"), "New drift", ""},

		// Unreadable means unknown: it is neither a fix nor a new finding.
		{"became unreadable", res("C-1", compare.Drift, "0"), res("C-1", compare.Error, "unreadable"), "Changed values", ""},
		{"was unreadable, now drifting", res("C-1", compare.Error, "unreadable"), res("C-1", compare.Drift, "0"), "Changed values", ""},
		{"unreadable both times", res("C-1", compare.Error, "unreadable"), res("C-1", compare.Error, "unreadable"), "none", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := compareScans(scanOf(tt.from), scanOf(tt.to))
			if got := groupOf(c, "C-1"); got != tt.want {
				t.Errorf("C-1 is in %q, want %q", got, tt.want)
			}
			if tt.want == "none" && c.Total() != 0 {
				t.Errorf("Total() = %d, want 0", c.Total())
			}
			if tt.want != "none" && c.Total() != 1 {
				t.Errorf("Total() = %d, want 1: a check must land in exactly one group", c.Total())
			}
		})
	}
}

func TestCompareScansChecksOnlyInOneScan(t *testing.T) {
	from := scanOf(res("GONE-1", compare.Drift, "0"), res("BOTH-1", compare.Compliant, "1"))
	to := scanOf(res("BOTH-1", compare.Compliant, "1"), res("NEW-1", compare.Compliant, "1"))

	c := compareScans(from, to)
	for id, want := range map[string]string{
		"GONE-1": "Only in one scan",
		"NEW-1":  "Only in one scan",
		"BOTH-1": "none",
	} {
		if got := groupOf(c, id); got != want {
			t.Errorf("%s is in %q, want %q", id, got, want)
		}
	}
	if len(c.OnlyInOne) != 2 {
		t.Errorf("OnlyInOne has %d rows, want 2", len(c.OnlyInOne))
	}
}

func TestCompareScansSortsBySeverity(t *testing.T) {
	low := res("LOW-1", compare.Drift, "0")
	low.Severity = "low"
	medium := res("MED-1", compare.Drift, "0")
	medium.Severity = "medium"
	high := res("HIGH-1", compare.Drift, "0")

	from := scanOf(res("LOW-1", compare.Compliant, "1"), res("MED-1", compare.Compliant, "1"), res("HIGH-1", compare.Compliant, "1"))
	c := compareScans(from, scanOf(low, medium, high))
	var ids []string
	for _, d := range c.NewDrift {
		ids = append(ids, d.ID)
	}
	if strings.Join(ids, ",") != "HIGH-1,MED-1,LOW-1" {
		t.Errorf("New drift order = %v, want the most severe first", ids)
	}
}

// The grouping has to survive the page: a check has to appear under its own
// heading and not under another.
func TestComparePagePutsAChecksRowUnderTheRightHeading(t *testing.T) {
	s, saved := testServer(t)
	// The fixture has SVC-001 compliant in the first scan and drifting after.
	target := "/compare?a=" + saved[0].File + "&b=" + saved[1].File
	rec := get(t, s, target)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", target, rec.Code)
	}
	body := rec.Body.String()

	at := func(what string) int {
		i := strings.Index(body, what)
		if i < 0 {
			t.Fatalf("the page does not contain %q", what)
		}
		return i
	}
	// SVC-001 is listed between the New drift heading and the Fixed heading,
	// which is the only place it belongs.
	newDrift, fixed, row := at("New drift"), at("Fixed <span"), at("SVC-001")
	if !(newDrift < row && row < fixed) {
		t.Errorf("SVC-001 is at %d, want it between New drift (%d) and Fixed (%d)", row, newDrift, fixed)
	}
	// And it is only listed once, so it cannot also be under another heading.
	if n := strings.Count(body, "SVC-001"); n != 1 {
		t.Errorf("SVC-001 appears %d times, want once", n)
	}
	// Both statuses are spelled out, not just coloured.
	if !strings.Contains(body, "COMPLIANT") || !strings.Contains(body, "DRIFT") {
		t.Error("the comparison should name both statuses as text")
	}
}

func TestComparePageRejectsAScanOutsideTheLedger(t *testing.T) {
	s, saved := testServer(t)
	for _, target := range []string{
		"/compare?a=../baseline.yaml&b=" + saved[0].File,
		"/compare?a=" + saved[0].File + "&b=notes.json",
	} {
		if rec := get(t, s, target); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", target, rec.Code)
		}
	}
}
