// Package report prints scan results and saves them as JSON evidence.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ttran0012/winbaseline/internal/compare"
)

// Scan is the saved record of one run.
type Scan struct {
	Host            string           `json:"host"`
	StartedAt       time.Time        `json:"started_at"`
	BaselineName    string           `json:"baseline_name"`
	BaselineVersion string           `json:"baseline_version"`
	Summary         Summary          `json:"summary"`
	Results         []compare.Result `json:"results"`
}

// Summary counts results by status.
type Summary struct {
	Total     int `json:"total"`
	Compliant int `json:"compliant"`
	Drift     int `json:"drift"`
	Errors    int `json:"errors"`
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
		default:
			s.Errors++
		}
	}
	return s
}

// Print writes a readable table and summary.
func Print(w io.Writer, s Scan) {
	fmt.Fprintf(w, "Host: %s   Baseline: %s v%s   Time: %s\n\n",
		s.Host, s.BaselineName, s.BaselineVersion, s.StartedAt.Format(time.RFC1123))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tSEVERITY\tEXPECTED\tACTUAL\tSETTING")
	for _, r := range s.Results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Status, strings.ToUpper(r.Severity), r.Expected, r.Actual, r.Title)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d checks: %d compliant, %d drift, %d errors\n",
		s.Summary.Total, s.Summary.Compliant, s.Summary.Drift, s.Summary.Errors)
}

// Save writes the scan as JSON and returns the file path and its SHA-256 hash.
func Save(dir string, s Scan) (string, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", "", err
	}
	name := fmt.Sprintf("scan-%s-%s.json", s.Host, s.StartedAt.Format("20060102-150405"))
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:]), nil
}
