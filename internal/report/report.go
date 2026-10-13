// Package report prints scan results and saves them as hash-chained JSON evidence.
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
	Elevated        bool             `json:"elevated"`
	BaselineName    string           `json:"baseline_name"`
	BaselineVersion string           `json:"baseline_version"`
	PreviousHash    string           `json:"previous_hash"`
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
	fmt.Fprintf(w, "Host: %s   Baseline: %s v%s   Time: %s   Administrator: %v\n\n",
		s.Host, s.BaselineName, s.BaselineVersion, s.StartedAt.Format(time.RFC1123), s.Elevated)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATUS\tSEVERITY\tEXPECTED\tACTUAL\tSETTING")
	for _, r := range s.Results {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Status, strings.ToUpper(r.Severity), r.Expected, clip(r.Actual, 40), r.Title)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d checks: %d compliant, %d drift, %d errors\n",
		s.Summary.Total, s.Summary.Compliant, s.Summary.Drift, s.Summary.Errors)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// Save writes the scan as JSON, links it to the previous scan in the evidence
// chain, and returns the file path and its SHA-256 hash.
func Save(dir string, s Scan) (string, string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	lock, err := lockDir(dir)
	if err != nil {
		return "", "", fmt.Errorf("lock evidence chain: %w", err)
	}
	defer func() { _ = lock.unlock() }()
	prev, err := lastHash(dir)
	if err != nil {
		return "", "", fmt.Errorf("read evidence chain: %w", err)
	}
	s.PreviousHash = prev
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", "", err
	}
	stamp := strings.Replace(s.StartedAt.Format("20060102-150405.000"), ".", "-", 1)
	name := fmt.Sprintf("scan-%s-%s.json", s.Host, stamp)
	path := filepath.Join(dir, name)
	if err := writeNew(path, data); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(data)
	hash := hex.EncodeToString(sum[:])
	if err := appendChain(dir, ChainEntry{File: name, Hash: hash, PreviousHash: prev}); err != nil {
		return "", "", fmt.Errorf("update evidence chain: %w", err)
	}
	return path, hash, nil
}

// writeNew writes a file that must not already exist, so saved evidence is never overwritten.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("refusing to overwrite existing evidence: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
