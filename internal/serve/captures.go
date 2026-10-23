package serve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/ttran0012/winbaseline/internal/capture"
	"github.com/ttran0012/winbaseline/internal/report"
)

// The approval history is the list of baselines a computer has been signed off
// with. It is read the same careful way scans are: only files the capture
// ledger vouches for, each hash-checked against the line that recorded it, so a
// file dropped into the folder is never shown as an approval and a tampered one
// is shown as unverified rather than trusted.

// approvalView is one entry in a computer's approval history, as a page shows it.
type approvalView struct {
	File        string
	When        time.Time
	By          string
	Note        string
	SourceScan  string
	Excluded    []string
	FromCapture bool // made by -capture, with no reviewer sign-off
	Verified    bool // the file still hashes to what the ledger recorded
}

// hasCapture reports whether an approved baseline has been recorded for the
// computer whose evidence lives in dir. A broken or absent ledger counts as
// none: the scan's own CaptureStatus flags a capture that cannot be trusted.
func hasCapture(dir string) bool {
	entries, err := report.ReadChain(captureFolder(dir))
	return err == nil && len(entries) > 0
}

// captureHistory returns every approved baseline for the computer in dir,
// newest first.
func captureHistory(dir string) []approvalView {
	capDir := captureFolder(dir)
	entries, err := report.ReadChain(capDir)
	if err != nil {
		return nil
	}
	out := make([]approvalView, 0, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		view := approvalView{File: e.File}
		data, err := os.ReadFile(filepath.Join(capDir, e.File))
		if err != nil {
			out = append(out, view)
			continue
		}
		sum := sha256.Sum256(data)
		view.Verified = hex.EncodeToString(sum[:]) == e.Hash
		var c capture.Capture
		if err := json.Unmarshal(data, &c); err != nil {
			out = append(out, view)
			continue
		}
		view.When, view.By = c.CapturedAt, c.CapturedBy
		if c.Approval != nil {
			view.Note = c.Approval.Note
			view.SourceScan = c.Approval.SourceScan
			view.Excluded = c.Approval.ExcludedChecks
		} else {
			view.FromCapture = true
		}
		out = append(out, view)
	}
	return out
}
