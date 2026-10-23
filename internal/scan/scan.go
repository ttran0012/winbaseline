// Package scan reads one computer against a baseline and saves the evidence.
//
// This is the work itself, kept apart from the command line so that the
// dashboard can start the same scan and produce byte-identical evidence. It
// reads settings and writes evidence files; it changes nothing on the computer
// it reads.
package scan

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/capture"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// Target is one computer to read, and where its evidence goes. A target with no
// host is the computer this is running on, whose evidence stays in the results
// folder itself.
type Target struct {
	Host  string
	Label string
	Dir   string
}

// Options are the facts about this run that every scan records.
type Options struct {
	Baseline  *baseline.Baseline
	LocalHost string // the computer doing the reading
	At        time.Time
	Elevated  bool
}

// Read runs every check in the baseline against one computer and returns the
// scan. A computer that cannot be reached is not an error: every check records
// why it could not be read, and that is saved as evidence of the attempt. A
// capture that cannot be trusted is not an error either; the scan goes ahead
// and CaptureStatus records why it reports no changes.
func Read(t Target, o Options) report.Scan {
	c := collect.New()
	if t.Host != "" {
		c = collect.NewRemote(t.Host)
	}
	defer func() { _ = c.Close() }()

	host, from := o.LocalHost, ""
	if t.Host != "" {
		host, from = t.Host, o.LocalHost
	}
	s := report.Scan{
		Host:            host,
		ScannedFrom:     from,
		StartedAt:       o.At,
		Elevated:        o.Elevated,
		BaselineName:    o.Baseline.Name,
		BaselineVersion: o.Baseline.Version,
	}

	approved, err := capture.Latest(filepath.Join(t.Dir, capture.Dir), host)
	if err != nil {
		s.CaptureStatus = report.CaptureStatusRejected + err.Error()
	}
	var values map[string]string
	if approved != nil {
		values = approved.Capture.Values()
		s.Capture = &report.CaptureRef{
			File:       approved.File,
			Hash:       approved.Hash,
			CapturedAt: approved.Capture.CapturedAt,
		}
	}

	for _, chk := range o.Baseline.Checks {
		reading := c.Read(chk)
		res := compare.ApplyExceptions(compare.Evaluate(chk, reading), o.Baseline.Exceptions, host, o.At)
		// Record the normalized value on every scan, so a later reviewer can
		// approve this saved scan as the baseline without reading the computer
		// again. It is also what a change is measured against.
		res.Normalized = capture.Normalize(chk, reading)
		if approved != nil {
			was, inCapture := values[chk.ID]
			res = compare.ApplyChange(res, was, res.Normalized, inCapture)
		}
		s.Results = append(s.Results, res)
	}
	s.Summary = report.Summarize(s.Results)
	return s
}

// Saved is where one scan's evidence ended up.
type Saved struct {
	Entry    report.ChainEntry
	JSONPath string
	HTMLPath string // empty when no HTML view was written
	HTMLErr  string // set when the evidence saved but its HTML view did not
}

// Save writes the scan as chained evidence, and the HTML view beside it. The
// evidence is saved first, so a failed HTML view never loses a scan.
func Save(t Target, s report.Scan, writeHTML bool) (Saved, error) {
	entry, err := report.Save(t.Dir, s)
	if err != nil {
		return Saved{}, fmt.Errorf("save results: %w", err)
	}
	saved := Saved{Entry: entry, JSONPath: filepath.Join(t.Dir, entry.File)}
	if writeHTML {
		path, err := report.SaveHTML(t.Dir, s, entry)
		if err != nil {
			saved.HTMLErr = err.Error()
		} else {
			saved.HTMLPath = path
		}
	}
	return saved, nil
}

// ExitCode is what a run reports to whatever started it. A computer that
// answered nothing comes first, because none of the other answers mean anything
// then; evidence that cannot be trusted comes next; drift beats a change that
// policy still allows; and approved exceptions are neither.
func ExitCode(s report.Scan) int {
	switch {
	case s.Summary.Total > 0 && s.Summary.Errors == s.Summary.Total:
		return 2
	case s.CaptureStatus != "":
		return 3
	case s.Summary.Drift > 0:
		return 1
	case s.Summary.Changed > 0:
		return 4
	}
	return 0
}
