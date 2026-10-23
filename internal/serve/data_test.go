package serve

import (
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// settled builds a computer whose latest scan verified and found nothing.
func settled(summary report.Summary) computer {
	return computer{
		Key:  "SQL-02",
		Host: "SQL-02",
		Latest: &savedScan{
			Verified: true,
			Scan:     report.Scan{Host: "SQL-02", StartedAt: testNow.Add(-time.Hour), Summary: summary},
		},
	}
}

func TestComputerState(t *testing.T) {
	withCapture := settled(report.Summary{Total: 35, Compliant: 34, Changed: 1})
	withCapture.Latest.Scan.Capture = &report.CaptureRef{File: "capture.json"}

	rejected := settled(report.Summary{Total: 35, Compliant: 35})
	rejected.Latest.Scan.CaptureStatus = report.CaptureStatusRejected + "it was modified"

	unverified := settled(report.Summary{Total: 35, Compliant: 35})
	unverified.Latest.Verified = false

	broken := settled(report.Summary{Total: 35, Compliant: 35})
	broken.ChainErr = "the ledger is malformed"

	stale := settled(report.Summary{Total: 35, Compliant: 35})
	stale.Stale = true

	tests := []struct {
		name string
		c    computer
		want string
	}{
		{"never scanned", computer{Key: "SQL-02", Host: "SQL-02"}, StateNeverScanned},
		{"nothing could be read", settled(report.Summary{Total: 35, Errors: 35}), StateUnreadable},
		// A remote scan cannot read audit policy, so part of the picture is
		// missing even though the rest of it is fine.
		{"some checks could not be read", settled(report.Summary{Total: 35, Compliant: 28, Errors: 7}), StatePartial},
		{"drift and some unreadable is still partial",
			settled(report.Summary{Total: 35, Compliant: 27, Drift: 1, Errors: 7}), StatePartial},
		{"stopped reporting", stale, StateStale},
		{"broken chain", broken, StateChainBroken},
		{"unverified file", unverified, StateUnverified},
		{"capture rejected", rejected, StateCaptureGone},
		{"drift", settled(report.Summary{Total: 35, Compliant: 34, Drift: 1}), StateDrift},
		{"changed since capture", withCapture, StateChanged},
		{"clean", settled(report.Summary{Total: 35, Compliant: 35}), StateClean},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.c.State()
			if got != tt.want {
				t.Errorf("State() = %q, want %q", got, tt.want)
			}
			// The badge and the sort read off the same list, so a state that is
			// shown must also have a place in the order.
			if tt.c.Attention() >= len(stateOrder) {
				t.Errorf("state %q has no place in the order", got)
			}
		})
	}
}

// PARTIAL belongs after UNREADABLE and before DRIFT: a computer that answered
// nothing is worse than one that half answered, and a half-answered computer is
// worse than one that answered fully and is drifting, because part of it is
// still unknown.
func TestPartialSortsAfterUnreadableAndBeforeDrift(t *testing.T) {
	rank := func(state string) int {
		for i, s := range stateOrder {
			if s == state {
				return i
			}
		}
		t.Fatalf("%q is not in the order", state)
		return -1
	}
	if !(rank(StateUnreadable) < rank(StatePartial) && rank(StatePartial) < rank(StateDrift)) {
		t.Errorf("order is unreadable=%d partial=%d drift=%d; want unreadable before partial before drift",
			rank(StateUnreadable), rank(StatePartial), rank(StateDrift))
	}

	// And the fleet sort really does put them in that order.
	unreadable := settled(report.Summary{Total: 35, Errors: 35})
	unreadable.Host = "b-unreadable"
	partial := settled(report.Summary{Total: 35, Compliant: 28, Errors: 7})
	partial.Host = "a-partial"
	drifting := settled(report.Summary{Total: 35, Compliant: 30, Drift: 5})
	drifting.Host = "c-drifting"
	clean := settled(report.Summary{Total: 35, Compliant: 35})
	clean.Host = "d-clean"

	// Deliberately the wrong way round, and with host names that would sort
	// differently if urgency were not what decides.
	got := []computer{clean, drifting, partial, unreadable}
	sort.SliceStable(got, func(i, j int) bool { return got[i].Attention() < got[j].Attention() })

	want := []string{"b-unreadable", "a-partial", "c-drifting", "d-clean"}
	for i, host := range want {
		if got[i].Host != host {
			t.Errorf("position %d = %s, want %s", i, got[i].Host, host)
		}
	}
}

// A page that has moved should not turn a bookmark into a dead end.
func TestOldAddressesStillLandSomewhere(t *testing.T) {
	s, _ := testServer(t)
	tests := map[string]string{
		"/scans":              "/computer",
		"/scans?host=LAB-WIN": "/computer?host=LAB-WIN",
		"/job":                "/scan",
	}
	for from, want := range tests {
		t.Run(from, func(t *testing.T) {
			rec := get(t, s, from)
			if rec.Code != http.StatusFound {
				t.Fatalf("GET %s = %d, want 302", from, rec.Code)
			}
			if got := rec.Header().Get("Location"); got != want {
				t.Errorf("Location = %q, want %q", got, want)
			}
		})
	}
}

// A computer can only be opened by a folder name the dashboard found, so a
// crafted ?host= cannot reach a path of its own.
func TestComputerPageNeedsAKnownFolder(t *testing.T) {
	s, _ := testServer(t)
	for _, host := range []string{"SQL-99", "../..", `..\..`, "captures", "/etc", "C:\\Windows"} {
		if rec := get(t, s, "/computer?host="+host); rec.Code != http.StatusNotFound {
			t.Errorf("GET /computer?host=%s = %d, want 404", host, rec.Code)
		}
	}
	if rec := get(t, s, "/computer"); rec.Code != http.StatusOK {
		t.Errorf("GET /computer for this computer = %d, want 200", rec.Code)
	}
}

// The fleet page has to name a computer that is approved but has never been
// scanned: that is a gap, not an absence of news.
func TestFleetListsApprovedComputersWithNoEvidence(t *testing.T) {
	s, _ := testServer(t)
	s.hostsPath = hostList(t, s.dir, "SQL-02", "2026-12-31")

	body := get(t, s, "/").Body.String()
	for _, want := range []string{"SQL-02", StateNeverScanned, "Approved in the host list, but never scanned"} {
		if !strings.Contains(body, want) {
			t.Errorf("the fleet page is missing %q", want)
		}
	}
}

// A result that is only partly readable must not be reported as compliant.
func TestPartialComputerIsNotCalledClean(t *testing.T) {
	results := []compare.Result{
		{ID: "REG-001", Status: compare.Compliant, Severity: "high"},
		{ID: "AUD-001", Status: compare.Error, Severity: "medium",
			Note: "audit policy cannot be read remotely"},
	}
	c := settled(report.Summarize(results))
	c.Latest.Scan.Results = results

	if got := c.State(); got != StatePartial {
		t.Errorf("State() = %q, want %q", got, StatePartial)
	}
	if c.Settled() {
		t.Error("a partly readable computer should not count as settled")
	}
}
