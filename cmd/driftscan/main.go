//go:build windows

// Command driftscan compares this computer's configuration with a baseline
// and reports any drift. It only reads settings; it never changes them.
//
// Exit codes: 0 all compliant, 1 drift found, 2 the scan could not run,
// 3 evidence verification failed.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

func main() {
	baselinePath := flag.String("baseline", `baseline\windows11-baseline.yaml`, "path to the baseline YAML file")
	outDir := flag.String("out", "results", "folder for saved scan results")
	verify := flag.Bool("verify", false, "verify the saved evidence chain instead of scanning")
	flag.Parse()

	if *verify {
		n, err := report.Verify(*outDir)
		if err != nil {
			fmt.Printf("EVIDENCE CHAIN BROKEN after %d valid scan(s): %v\n", n, err)
			os.Exit(3)
		}
		fmt.Printf("Evidence chain OK: %d scan(s) verified in %s\n", n, *outDir)
		return
	}

	b, err := baseline.Load(*baselinePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	elevated := collect.IsElevated()
	if !elevated {
		fmt.Println("WARNING: not running as administrator; some settings (such as audit policy) cannot be read.")
		fmt.Println()
	}

	host, _ := os.Hostname()
	scan := report.Scan{
		Host:            host,
		StartedAt:       time.Now(),
		Elevated:        elevated,
		BaselineName:    b.Name,
		BaselineVersion: b.Version,
	}
	c := collect.New()
	for _, chk := range b.Checks {
		scan.Results = append(scan.Results, compare.Evaluate(chk, c.Read(chk)))
	}
	scan.Summary = report.Summarize(scan.Results)

	report.Print(os.Stdout, scan)

	path, hash, err := report.Save(*outDir, scan)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error saving results:", err)
		os.Exit(2)
	}
	fmt.Printf("\nResults saved: %s\nSHA-256: %s (linked to previous scan in %s)\n", path, hash, report.ChainLog)

	if scan.Summary.Drift > 0 {
		os.Exit(1) // lets Task Scheduler flag drift
	}
}
