// Package report prints scan results and saves them as hash-chained JSON evidence.
package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ttran0012/winbaseline/internal/compare"
)

// Scan is the saved record of one run.
type Scan struct {
	Host            string           `json:"host"`
	ScannedFrom     string           `json:"scanned_from,omitempty"` // set when another computer read this one
	StartedAt       time.Time        `json:"started_at"`
	Elevated        bool             `json:"elevated"`
	BaselineName    string           `json:"baseline_name"`
	BaselineVersion string           `json:"baseline_version"`
	PreviousHash    string           `json:"previous_hash"`
	Capture         *CaptureRef      `json:"capture,omitempty"`
	CaptureStatus   string           `json:"capture_status,omitempty"`
	Summary         Summary          `json:"summary"`
	Results         []compare.Result `json:"results"`
}

// CaptureStatusRejected prefixes the reason a scan was not compared with a
// capture. A scan whose CaptureStatus is set reports no changes at all: the
// policy checks ran as usual, but nothing could be said about what changed.
const CaptureStatusRejected = "rejected: "

// CaptureRef names the approved capture a scan was compared with, so the
// evidence records which recorded configuration the changes are measured
// against. It is absent when the computer has no capture.
type CaptureRef struct {
	File       string    `json:"file"`
	Hash       string    `json:"hash"`
	CapturedAt time.Time `json:"captured_at"`
}

// Summary counts results by status, and how many changed since the capture.
type Summary struct {
	Total      int `json:"total"`
	Compliant  int `json:"compliant"`
	Drift      int `json:"drift"`
	Exceptions int `json:"exceptions"`
	Errors     int `json:"errors"`
	Changed    int `json:"changed"`
}

// Summarize counts the results.
func Summarize(rs []compare.Result) Summary {
	s := Summary{Total: len(rs)}
	for _, r := range rs {
		switch r.Status {
		case compare.Compliant:
			s.Compliant++
		case compare.Drift:
			s.Drift++
		case compare.Exception:
			s.Exceptions++
		default:
			s.Errors++
		}
		if r.Change == compare.Changed {
			s.Changed++
		}
	}
	return s
}

// Print writes a readable table and summary. The change column appears only
// when the scan was compared with a capture, so a computer that has none prints
// exactly as it did before captures existed.
func Print(w io.Writer, s Scan) {
	fmt.Fprintf(w, "Host: %s   Baseline: %s v%s   Time: %s   Administrator: %v\n",
		s.Host, s.BaselineName, s.BaselineVersion, s.StartedAt.Format(time.RFC1123), s.Elevated)
	if s.Capture != nil {
		fmt.Fprintf(w, "Compared with capture: %s (recorded %s)\n",
			s.Capture.File, s.Capture.CapturedAt.Format(time.RFC1123))
	}
	if s.CaptureStatus != "" {
		fmt.Fprintln(w, "\n***")
		fmt.Fprintln(w, "*** WARNING: this scan was NOT compared with an approved capture.")
		fmt.Fprintf(w, "***   %s\n", s.CaptureStatus)
		fmt.Fprintln(w, "***   The policy checks below ran as usual, but nothing can be said about")
		fmt.Fprintln(w, "***   what changed. Run driftscan -verify to see where the capture chain broke.")
		fmt.Fprintln(w, "***")
	}
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	columns := func(id, status, change string, rest ...string) {
		row := []string{id, status}
		if s.Capture != nil {
			row = append(row, change)
		}
		fmt.Fprintln(tw, strings.Join(append(row, rest...), "\t"))
	}
	columns("ID", "STATUS", "CHANGE", "SEVERITY", "EXPECTED", "ACTUAL", "SETTING")
	for _, r := range s.Results {
		columns(r.ID, r.Status, r.Change, strings.ToUpper(r.Severity), r.Expected, clip(r.Actual, 40), r.Title)
	}
	tw.Flush()

	fmt.Fprintf(w, "\n%d checks: %d compliant, %d drift, %d approved exceptions, %d errors",
		s.Summary.Total, s.Summary.Compliant, s.Summary.Drift, s.Summary.Exceptions, s.Summary.Errors)
	if s.Capture != nil {
		fmt.Fprintf(w, ", %d changed since capture %s",
			s.Summary.Changed, s.Capture.CapturedAt.Format("2006-01-02"))
	}
	fmt.Fprintln(w)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// LinkPrevious stores the hash of the scan saved before this one, which is what
// makes the saved evidence a chain. SaveChained calls it.
func (s *Scan) LinkPrevious(hash string) { s.PreviousHash = hash }

// Save writes the scan as JSON, links it to the previous scan in the evidence
// chain, and returns the chain entry: the file it wrote, that file's SHA-256
// hash, and the hash of the scan before it.
func Save(dir string, s Scan) (ChainEntry, error) {
	return SaveChained(dir, RecordName("scan", s.Host, s.StartedAt)+".json", &s)
}
