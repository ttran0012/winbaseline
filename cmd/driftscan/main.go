//go:build windows

// Command driftscan compares this computer's configuration with a baseline
// and reports any drift. It only reads settings; it never changes them.
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
	flag.Parse()

	b, err := baseline.Load(*baselinePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	host, _ := os.Hostname()
	scan := report.Scan{
		Host:            host,
		StartedAt:       time.Now(),
		BaselineName:    b.Name,
		BaselineVersion: b.Version,
	}
	for _, c := range b.Checks {
		reading := collect.RegistryDWORD(c.Path, c.Value)
		scan.Results = append(scan.Results, compare.Evaluate(c, reading))
	}
	scan.Summary = report.Summarize(scan.Results)

	report.Print(os.Stdout, scan)

	path, hash, err := report.Save(*outDir, scan)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error saving results:", err)
		os.Exit(2)
	}
	fmt.Printf("\nResults saved: %s\nSHA-256: %s\n", path, hash)

	if scan.Summary.Drift > 0 {
		os.Exit(1) // non-zero exit lets scheduled tasks flag drift
	}
}
