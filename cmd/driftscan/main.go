//go:build windows

// Command driftscan compares a computer's configuration with a baseline and
// reports any drift. With -capture it instead records the configuration the
// computer is approved with, so that later scans can also report what changed
// since it was approved. With -hosts it reads other computers named in an
// approved host list, over the network, as the account running it. With -serve
// it reads nothing but the results already saved, and shows them as a dashboard
// on the loopback interface.
//
// It only ever reads settings. Nothing is changed on any computer it reads, and
// nothing is installed on one.
//
// Exit codes: 0 nothing to report, 1 drift found, 2 the run could not finish or
// a computer could not be read at all, 3 evidence verification failed,
// including a capture folder that could no longer be trusted, 4 no drift, but
// something changed since the approved capture. With -hosts the code is the
// loudest of the computers scanned.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/capture"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/fleet"
	"github.com/ttran0012/winbaseline/internal/report"
	"github.com/ttran0012/winbaseline/internal/scan"
	"github.com/ttran0012/winbaseline/internal/serve"
)

// run is what one invocation needs: the parsed flags and the facts about this
// computer, settled once before any reading starts.
type run struct {
	baselineDir string             // -baselines: folder of baselines chosen by role
	forced      *baseline.Baseline // -baseline: one baseline for every computer, or nil
	forcedName  string             // the forced file's name, for the record
	outDir      string
	captureDir  string
	host        string // the computer this is running on
	at          time.Time
	elevated    bool
	writeHTML   bool
}

func main() {
	baselineFile := flag.String("baseline", "", "force one baseline file for every computer, overriding role and the host list")
	baselineDir := flag.String("baselines", "baseline", "folder of baseline files; a computer's role picks one when the host list does not name it")
	outDir := flag.String("out", "results", "folder for saved scan results")
	writeHTML := flag.Bool("html", true, "also write a readable HTML report beside each saved JSON result")
	captureNow := flag.Bool("capture", false, "record this computer's current configuration as its approved capture, instead of scanning")
	propose := flag.Bool("propose-exceptions", false, "with -capture, also write a draft exceptions list for every check that is drifting")
	hostsPath := flag.String("hosts", "", "path to an approved host list; scans those computers over the network instead of this one")
	onlyHost := flag.String("host", "", "with -hosts, scan only this computer from the list")
	verify := flag.Bool("verify", false, "verify the saved evidence chains instead of scanning")
	dashboard := flag.Bool("serve", false, "serve a read-only dashboard over the saved results instead of scanning")
	addr := flag.String("addr", "127.0.0.1:8080", "address for -serve; must be a loopback address")
	flag.Parse()

	if *verify {
		verifyChains(*outDir)
		return
	}
	if *dashboard {
		serveDashboard(*addr, *outDir, *baselineDir, *baselineFile, *hostsPath, *writeHTML)
		return
	}

	var forced *baseline.Baseline
	var forcedName string
	if *baselineFile != "" {
		b, err := baseline.Load(*baselineFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(2)
		}
		forced, forcedName = b, filepath.Base(*baselineFile)
	}

	host, _ := os.Hostname()
	r := run{
		baselineDir: *baselineDir,
		forced:      forced,
		forcedName:  forcedName,
		outDir:      *outDir,
		captureDir:  filepath.Join(*outDir, capture.Dir),
		host:        host,
		at:          time.Now(),
		elevated:    collect.IsElevated(),
		writeHTML:   *writeHTML,
	}

	if *hostsPath != "" {
		if *captureNow {
			// A capture has to be able to read everything, and audit policy
			// cannot be read from another computer at all.
			fmt.Fprintln(os.Stderr, "error: -capture has to run on the computer being captured:")
			fmt.Fprintln(os.Stderr, " ", collect.ErrAuditNeedsLocalAccess)
			os.Exit(2)
		}
		r.scanFleet(*hostsPath, *onlyHost)
		return
	}
	if *onlyHost != "" {
		fmt.Fprintln(os.Stderr, "error: -host names a computer from the list given to -hosts, which approves scanning it")
		os.Exit(2)
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

// serveDashboard runs the read-only dashboard until it is interrupted. The
// address is checked before anything is printed, so a refused address never
// leaves a URL on screen that nothing is listening on.
func serveDashboard(addr, outDir, baselineDir, baselineFile, hostsPath string, writeHTML bool) {
	if err := serve.CheckLoopback(addr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	s := serve.New(serve.Options{
		Dir:          outDir,
		BaselineDir:  baselineDir,
		BaselineFile: baselineFile,
		HostsPath:    hostsPath,
		WriteHTML:    writeHTML,
		Addr:         addr,
	})
	fmt.Printf("Dashboard: http://%s/\n", addr)
	fmt.Printf("Evidence folder: %s\n", outDir)
	if hostsPath == "" {
		fmt.Println("No -hosts list given, so the dashboard can only scan this computer.")
	} else {
		fmt.Printf("Approved host list: %s\n", hostsPath)
	}
	fmt.Println("A scan started here reads settings and writes evidence. It changes nothing on any computer.")
	fmt.Println("Press Ctrl+C to stop.")
	if err := s.ListenAndServe(addr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

// verifyChains checks every ledger under the results folder: the scans and
// captures of this computer, and of each computer with a folder of its own.
func verifyChains(outDir string) {
	folders := []string{outDir}
	if entries, err := os.ReadDir(outDir); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Name() != capture.Dir {
				folders = append(folders, filepath.Join(outDir, e.Name()))
			}
		}
	}

	checked, ok := 0, true
	for _, dir := range folders {
		for _, c := range []struct{ dir, kind string }{
			{dir, "scan"},
			{filepath.Join(dir, capture.Dir), "capture"},
		} {
			if _, err := os.Stat(filepath.Join(c.dir, report.ChainLog)); err != nil {
				continue // nothing recorded here
			}
			checked++
			n, err := report.Verify(c.dir)
			if err != nil {
				fmt.Printf("%s CHAIN BROKEN in %s after %d valid %s(s): %v\n",
					strings.ToUpper(c.kind), c.dir, n, c.kind, err)
				ok = false
				continue
			}
			fmt.Printf("%s chain OK: %d %s(s) verified in %s\n", c.kind, n, c.kind, c.dir)
		}
	}

	if checked == 0 {
		fmt.Printf("Nothing to verify: no %s found under %s\n", report.ChainLog, outDir)
		os.Exit(3)
	}
	if !ok {
		os.Exit(3)
	}
}

// recordCapture records this computer's configuration as approved, against the
// baseline its role (or -baseline) chooses, the same one a scan would use.
func (r run) recordCapture(propose bool) {
	b, _, err := r.selector(nil).Resolve(scan.Target{}, r.host)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	c, err := capture.Record(b, collect.New(), capture.Options{
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
	t := scan.Target{Dir: r.outDir}
	s, err := scan.Read(t, r.options(nil))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if s.CaptureStatus != "" {
		fmt.Fprintln(os.Stderr, "warning: the approved capture was not used:", s.CaptureStatus)
	}
	report.Print(os.Stdout, s)
	r.saveScan(t, s)
	os.Exit(scan.ExitCode(s))
}

// selector builds the baseline chooser for this run. perHost carries the host
// list's per-computer assignments when there is a host list, and is nil for a
// scan of this computer alone.
func (r run) selector(perHost map[string]string) scan.Selector {
	return scan.Selector{
		Folder:     r.baselineDir,
		Forced:     r.forced,
		ForcedName: r.forcedName,
		PerHost:    perHost,
	}
}

// options are the facts every scan this run takes records.
func (r run) options(perHost map[string]string) scan.Options {
	return scan.Options{
		Baselines: r.selector(perHost),
		LocalHost: r.host,
		At:        r.at,
		Elevated:  r.elevated,
	}
}

// saveScan writes one computer's evidence and says where it went.
func (r run) saveScan(t scan.Target, s report.Scan) {
	saved, err := scan.Save(t, s, r.writeHTML)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error saving results:", err)
		os.Exit(2)
	}
	fmt.Printf("\nResults saved: %s\nSHA-256: %s (linked to previous scan in %s)\n",
		saved.JSONPath, saved.Entry.Hash, report.ChainLog)
	switch {
	case saved.HTMLErr != "":
		// The evidence is already saved and chained, so a failed HTML view is
		// reported but does not change the outcome.
		fmt.Fprintln(os.Stderr, "warning:", saved.HTMLErr)
	case saved.HTMLPath != "":
		fmt.Printf("HTML report: %s\n", saved.HTMLPath)
	}
}

// scanFleet reads every computer the host list approves. Each one keeps its own
// folder of evidence, with its own chain, because a chain has one writer.
func (r run) scanFleet(hostsPath, only string) {
	hosts, err := fleet.LoadFrom(hostsPath, r.baselineDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if err := hosts.Authorized(r.at); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	targets, err := hosts.Targets(only)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	perHost := hosts.Baselines()

	a := hosts.Authorization
	fmt.Printf("Scanning %d computer(s) from %s, as %s.\n", len(targets), hostsPath, collect.CurrentUser())
	fmt.Printf("Approved by %s on %s, until %s: %s\n", a.ApprovedBy, a.Approved, a.Expires, a.Scope)
	if r.forced != nil {
		fmt.Printf("Baseline: %s (forced for every computer). Nothing on these computers is changed or installed.\n\n", r.forcedName)
	} else {
		fmt.Printf("Baselines chosen per computer from %s (the host list, else the computer's role). "+
			"Nothing on these computers is changed or installed.\n\n", r.baselineDir)
	}

	worst := 0
	for _, h := range targets {
		t := scan.Target{Host: h.Name, Label: h.Label, Dir: filepath.Join(r.outDir, h.Name)}
		s, err := scan.Read(t, r.options(perHost))
		if err != nil {
			fmt.Printf("%-20s could not choose a baseline: %v\n", h.Name, err)
			if worst < 2 {
				worst = 2
			}
			continue
		}
		code := scan.ExitCode(s)
		if code > worst {
			worst = code
		}
		sum := s.Summary
		fmt.Printf("%-20s %2d compliant  %2d drift  %2d exception  %2d error", h.Name,
			sum.Compliant, sum.Drift, sum.Exceptions, sum.Errors)
		if s.Capture != nil {
			fmt.Printf("  %2d changed", sum.Changed)
		}
		fmt.Printf("   exit %d   [%s]\n", code, s.BaselineName)
		if sum.Total > 0 && sum.Errors == sum.Total {
			fmt.Printf("%-20s   nothing could be read: %s\n", "", firstError(s))
		}
		if s.CaptureStatus != "" {
			fmt.Fprintf(os.Stderr, "warning: %s: the approved capture was not used: %s\n", h.Name, s.CaptureStatus)
		}
		r.saveScan(t, s)
	}

	fmt.Printf("\nEvidence saved under %s, one folder per computer. Verify it with -verify.\n", r.outDir)
	os.Exit(worst)
}

// firstError is the first reason a check could not be read, for the one-line
// summary of a computer that answered nothing.
func firstError(s report.Scan) string {
	for _, res := range s.Results {
		if res.Status == compare.Error && res.Note != "" {
			return res.Note
		}
	}
	return "no reason recorded"
}
