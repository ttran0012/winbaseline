// Package scan reads one computer against a baseline and saves the evidence.
//
// This is the work itself, kept apart from the command line so that the
// dashboard can start the same scan and produce byte-identical evidence. It
// reads settings and writes evidence files; it changes nothing on the computer
// it reads.
//
// Which baseline a computer is read against is settled here too, because a
// domain controller and a workstation are not held to the same policy. The host
// list may name a baseline for a computer; failing that, the computer's role
// chooses one; and -baseline overrides both with a single file for everything.
package scan

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/capture"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// The baseline files chosen by role when nothing else decides. They live in the
// -baselines folder.
const (
	BaselineWorkstation      = "windows11-baseline.yaml"
	BaselineMemberServer     = "windows-server-2025-ms-baseline.yaml"
	BaselineDomainController = "windows-server-2022-dc-baseline.yaml"
)

// BaselineForRole returns the default baseline file for a computer's DomainRole:
// a domain controller (4 or 5) and a member server (2 or 3) each have their own,
// and everything else is held to the workstation baseline.
func BaselineForRole(role int) string {
	switch role {
	case 4, 5:
		return BaselineDomainController
	case 2, 3:
		return BaselineMemberServer
	default:
		return BaselineWorkstation
	}
}

// Selector decides which baseline a computer is read against. The host list may
// assign one by name; otherwise the computer's role picks one from Folder; and
// a Forced baseline, from -baseline, overrides both.
type Selector struct {
	Folder     string             // the -baselines folder, where role-chosen files live
	Forced     *baseline.Baseline // -baseline: one baseline for every computer, already loaded
	ForcedName string             // the forced file's name, for the record
	PerHost    map[string]string  // lower(host) -> baseline file named by the host list
}

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
	Baselines Selector
	LocalHost string // the computer doing the reading
	At        time.Time
	Elevated  bool
}

// resolve chooses and loads the baseline for a host. readRole reads the host's
// role and is called only when neither a forced baseline nor a host-list
// assignment decides it; a role that cannot be read falls back to the
// workstation baseline, which is also the right default for an unreachable
// computer whose checks are about to all be unreadable anyway.
func (sel Selector) resolve(host string, readRole func() (int, error)) (*baseline.Baseline, string, error) {
	if sel.Forced != nil {
		return sel.Forced, sel.ForcedName, nil
	}
	file := sel.PerHost[strings.ToLower(host)]
	why := "the host list"
	if file == "" {
		if role, err := readRole(); err != nil {
			file, why = BaselineWorkstation, "the default, since the role could not be read"
		} else {
			file, why = BaselineForRole(role), fmt.Sprintf("the computer's role (%d)", role)
		}
	}
	if !validBaselineName(file) {
		return nil, file, fmt.Errorf("baseline %q (from %s) is not a plain file name in the baseline folder", file, why)
	}
	b, err := baseline.Load(filepath.Join(sel.Folder, file))
	if err != nil {
		return nil, file, fmt.Errorf("baseline %q (chosen by %s): %w", file, why, err)
	}
	return b, file, nil
}

// Resolve chooses and loads a target's baseline without running a scan, opening
// a collector only to read the role if it has to. It is for callers that need
// the baseline on its own, such as -capture.
func (sel Selector) Resolve(t Target, localHost string) (*baseline.Baseline, string, error) {
	c := collectorFor(t)
	defer func() { _ = c.Close() }()
	return sel.resolve(hostOf(t, localHost), c.DomainRole)
}

// validBaselineName rejects anything that is not a bare file name, so a host
// list cannot point the scanner at a file outside the baseline folder.
func validBaselineName(name string) bool {
	return name != "" && !strings.ContainsAny(name, `/\`) &&
		filepath.Base(name) == name && !strings.Contains(name, "..")
}

func collectorFor(t Target) *collect.Collector {
	if t.Host != "" {
		return collect.NewRemote(t.Host)
	}
	return collect.New()
}

func hostOf(t Target, localHost string) string {
	if t.Host != "" {
		return t.Host
	}
	return localHost
}

// Read runs every check in the chosen baseline against one computer and returns
// the scan. It errors only when no baseline can be chosen or loaded at all;
// a computer that cannot be reached is not an error, because every check
// records why it could not be read, and that is saved as evidence of the
// attempt. A capture that cannot be trusted is not an error either; the scan
// goes ahead and CaptureStatus records why it reports no changes.
func Read(t Target, o Options) (report.Scan, error) {
	c := collectorFor(t)
	defer func() { _ = c.Close() }()

	host, from := o.LocalHost, ""
	if t.Host != "" {
		host, from = t.Host, o.LocalHost
	}

	b, _, err := o.Baselines.resolve(host, c.DomainRole)
	if err != nil {
		return report.Scan{}, err
	}

	s := report.Scan{
		Host:            host,
		ScannedFrom:     from,
		StartedAt:       o.At,
		Elevated:        o.Elevated,
		BaselineName:    b.Name,
		BaselineVersion: b.Version,
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

	for _, chk := range b.Checks {
		reading := c.Read(chk)
		res := compare.ApplyExceptions(compare.Evaluate(chk, reading), b.Exceptions, host, o.At)
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
	return s, nil
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
