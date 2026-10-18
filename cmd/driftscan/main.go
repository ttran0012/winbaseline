//go:build windows

// Command driftscan compares this computer's configuration with a baseline and
// reports any drift. With -capture it instead records the configuration the
// computer is approved with, so that later scans can also report what changed
// since it was approved. It only reads settings; it never changes them.
//
// Exit codes: 0 nothing to report, 1 drift found, 2 the run could not finish,
// 3 evidence verification failed, including a capture folder that could no
// longer be trusted, 4 no drift, but something changed since the approved
// capture.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/capture"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// run is what one invocation needs: the parsed flags and the facts about this
// computer, settled once before any reading starts.
type run struct {
	baseline   *baseline.Baseline
	outDir     string
	captureDir string
	host       string
	at         time.Time
	elevated   bool
	writeHTML  bool
}

func main() {
	baselinePath := flag.String("baseline", `baseline\windows11-baseline.yaml`, "path to the baseline YAML file")
	outDir := flag.String("out", "results", "folder for saved scan results")
	writeHTML := flag.Bool("html", true, "also write a readable HTML report beside each saved JSON result")
	captureNow := flag.Bool("capture", false, "record this computer's current configuration as its approved capture, instead of scanning")
	propose := flag.Bool("propose-exceptions", false, "with -capture, also write a draft exceptions list for every check that is drifting")
	verify := flag.Bool("verify", false, "verify the saved evidence chains instead of scanning")
	flag.Parse()

	captureDir := filepath.Join(*outDir, capture.Dir)

	if *verify {
		verifyChains(*outDir, captureDir)
		return
	}

	b, err := baseline.Load(*baselinePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	host, _ := os.Hostname()
	r := run{
		baseline:   b,
		outDir:     *outDir,
		captureDir: captureDir,
		host:       host,
		at:         time.Now(),
		elevated:   collect.IsElevated(),
		writeHTML:  *writeHTML,
	}

	if *captureNow {
		r.recordCapture(*propose)
		return
	}
	if *propose {
		fmt.Fprintln(os.Stderr, "error: -propose-exceptions works with -capture, which decides which checks to propose")
		os.Exit(2)
	}
	r.scan()
}

// verifyChains checks the scans, and the captures when this computer has any.
func verifyChains(outDir, captureDir string) {
	n, err := report.Verify(outDir)
	if err != nil {
		fmt.Printf("EVIDENCE CHAIN BROKEN after %d valid scan(s): %v\n", n, err)
		os.Exit(3)
	}
	fmt.Printf("Evidence chain OK: %d scan(s) verified in %s\n", n, outDir)

	if _, err := os.Stat(filepath.Join(captureDir, report.ChainLog)); err != nil {
		return // nothing has been captured yet
	}
	m, err := report.Verify(captureDir)
	if err != nil {
		fmt.Printf("CAPTURE CHAIN BROKEN after %d valid capture(s): %v\n", m, err)
		os.Exit(3)
	}
	fmt.Printf("Capture chain OK: %d capture(s) verified in %s\n", m, captureDir)
}

// recordCapture records this computer's configuration as approved.
func (r run) recordCapture(propose bool) {
	c, err := capture.Record(r.baseline, collect.New(), capture.Options{
		Host:       r.host,
		CapturedBy: collect.CurrentUser(),
		At:         r.at,
		Elevated:   r.elevated,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	entry, err := capture.Save(r.captureDir, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error saving capture:", err)
		os.Exit(2)
	}
	fmt.Printf("Captured %d checks on %s as %s.\n", len(c.Entries), c.Host, c.CapturedBy)
	fmt.Printf("Capture saved: %s\nSHA-256: %s (linked to previous capture in %s)\n",
		filepath.Join(r.captureDir, entry.File), entry.Hash, report.ChainLog)

	drifting := c.Drifting()
	fmt.Printf("\n%d of the captured checks are drifting from the baseline policy.\n", len(drifting))
	if !propose {
		return
	}
	if len(drifting) == 0 {
		fmt.Println("Nothing to propose.")
		return
	}
	path, err := capture.SaveProposedExceptions(r.captureDir, c, r.at.AddDate(0, 0, capture.ProposedExceptionDays))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error writing proposed exceptions:", err)
		os.Exit(2)
	}
	fmt.Printf("Draft exceptions for those checks: %s\n", path)
	fmt.Printf("Fill in every %s and paste the entries you approve into the baseline yourself; the baseline file was not changed.\n",
		baseline.Placeholder)
}

// scan compares this computer with the baseline, and with its capture when it
// has one.
func (r run) scan() {
	if !r.elevated {
		fmt.Println("WARNING: not running as administrator; some settings (such as audit policy) cannot be read.")
		fmt.Println()
	}

	scan := report.Scan{
		Host:            r.host,
		StartedAt:       r.at,
		Elevated:        r.elevated,
		BaselineName:    r.baseline.Name,
		BaselineVersion: r.baseline.Version,
	}

	// A capture that cannot be trusted must not stop the policy checks: a
	// computer whose capture folder was tampered with is exactly the one worth
	// scanning. The scan goes ahead and is saved as usual, the evidence records
	// why no change was reported, and the run exits 3.
	approved, err := capture.Latest(r.captureDir, r.host)
	if err != nil {
		scan.CaptureStatus = report.CaptureStatusRejected + err.Error()
		fmt.Fprintln(os.Stderr, "warning: the approved capture was not used:", err)
	}

	var values map[string]string
	if approved != nil {
		values = approved.Capture.Values()
		scan.Capture = &report.CaptureRef{
			File:       approved.File,
			Hash:       approved.Hash,
			CapturedAt: approved.Capture.CapturedAt,
		}
	}

	c := collect.New()
	for _, chk := range r.baseline.Checks {
		reading := c.Read(chk)
		res := compare.ApplyExceptions(compare.Evaluate(chk, reading), r.baseline.Exceptions, r.host, r.at)
		if approved != nil {
			was, inCapture := values[chk.ID]
			res = compare.ApplyChange(res, was, capture.Normalize(chk, reading), inCapture)
		}
		scan.Results = append(scan.Results, res)
	}
	scan.Summary = report.Summarize(scan.Results)

	report.Print(os.Stdout, scan)

	entry, err := report.Save(r.outDir, scan)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error saving results:", err)
		os.Exit(2)
	}
	fmt.Printf("\nResults saved: %s\nSHA-256: %s (linked to previous scan in %s)\n",
		filepath.Join(r.outDir, entry.File), entry.Hash, report.ChainLog)

	if r.writeHTML {
		// The evidence is already saved and chained at this point, so a failed
		// HTML view is reported but does not change the scan's exit code.
		htmlPath, err := report.SaveHTML(r.outDir, scan, entry)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning:", err)
		} else {
			fmt.Printf("HTML report: %s\n", htmlPath)
		}
	}

	if code := exitCode(scan); code != 0 {
		os.Exit(code)
	}
}

// exitCode is what the run reports to Task Scheduler. Evidence that cannot be
// trusted comes first, because until that is sorted out nobody can say what
// changed on this computer; drift beats a change that policy still allows; and
// approved exceptions are neither.
func exitCode(s report.Scan) int {
	switch {
	case s.CaptureStatus != "":
		return 3
	case s.Summary.Drift > 0:
		return 1
	case s.Summary.Changed > 0:
		return 4
	}
	return 0
}
