// Package capture records the configuration a computer was approved with, so
// later scans can report what changed since then. That is a different question
// from the one the baseline answers: a setting can follow CIS policy and still
// have been changed by someone, and a deviation the organization decided to
// live with is not news every time the scanner runs.
package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// Dir is the folder inside the results folder where captures are kept. It has
// its own chain.log, so captures are hash-chained independently of scans and
// -verify can check both.
const Dir = "captures"

// ProposedExceptionDays is how long a proposed exception is drafted to last, so
// every approval written from a draft comes back for review within the year.
const ProposedExceptionDays = 90

// ErrNotElevated is returned when a capture is attempted without administrator
// rights. Capturing then would record the audit policy checks as unreadable and
// treat that as the approved configuration.
var ErrNotElevated = errors.New("a capture must run as administrator: without it the audit policy cannot be read, and \"unreadable\" would be recorded as this computer's approved configuration")

// Capture is the configuration one computer was approved with, at one moment.
type Capture struct {
	Host            string    `json:"host"`
	CapturedAt      time.Time `json:"captured_at"`
	CapturedBy      string    `json:"captured_by"`
	BaselineName    string    `json:"baseline_name"`
	BaselineVersion string    `json:"baseline_version"`
	PreviousHash    string    `json:"previous_hash"`
	// Approval is set when this capture was made by approving a reviewed scan
	// rather than by -capture; it names who signed it off and the scan it came
	// from. A capture read back from an older file simply has none.
	Approval *Approval `json:"approval,omitempty"`
	Entries  []Entry   `json:"entries"`
}

// Entry is the approved value of one check together with the policy status it
// had when it was approved, because a capture records what the computer really
// looked like, deviations included.
type Entry struct {
	ID     string `json:"id"`
	Value  string `json:"value"`
	Status string `json:"status"`
}

// LinkPrevious stores the hash of the capture saved before this one, which is
// what makes the saved captures a chain. report.SaveChained calls it.
func (c *Capture) LinkPrevious(hash string) { c.PreviousHash = hash }

// Values returns the approved value of every check, by check ID.
func (c *Capture) Values() map[string]string {
	v := make(map[string]string, len(c.Entries))
	for _, e := range c.Entries {
		v[e.ID] = e.Value
	}
	return v
}

// Drifting returns the IDs of the checks that were drifting when the capture
// was taken, in baseline order. Checks already covered by an approved exception
// are not included, because they do not need approving again.
func (c *Capture) Drifting() []string {
	var ids []string
	for _, e := range c.Entries {
		if e.Status == compare.Drift {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

// Reader reads the current value of one check. *collect.Collector satisfies it;
// tests supply their own.
type Reader interface {
	Read(baseline.Check) collect.Reading
}

// Options are the facts about this run that the capture records. Elevated is
// passed in rather than read from the system here, so that the refusal to
// capture an incomplete reading can be tested.
type Options struct {
	Host       string
	CapturedBy string
	At         time.Time
	Elevated   bool
}

// Record reads every check in the baseline and returns the capture. Approved
// exceptions are applied as a scan would apply them, so a deviation the
// organization already accepted is recorded as an exception and is not proposed
// for approval a second time.
func Record(b *baseline.Baseline, r Reader, o Options) (*Capture, error) {
	if !o.Elevated {
		return nil, ErrNotElevated
	}
	c := &Capture{
		Host:            o.Host,
		CapturedAt:      o.At,
		CapturedBy:      o.CapturedBy,
		BaselineName:    b.Name,
		BaselineVersion: b.Version,
	}
	for _, chk := range b.Checks {
		reading := r.Read(chk)
		res := compare.ApplyExceptions(compare.Evaluate(chk, reading), b.Exceptions, o.Host, o.At)
		c.Entries = append(c.Entries, Entry{
			ID:     chk.ID,
			Value:  Normalize(chk, reading),
			Status: res.Status,
		})
	}
	return c, nil
}

// Save writes the capture into dir as JSON and links it into the capture chain,
// returning the ledger entry. Captures are never overwritten.
func Save(dir string, c *Capture) (report.ChainEntry, error) {
	return report.SaveChained(dir, report.RecordName("capture", c.Host, c.CapturedAt)+".json", c)
}

// Loaded is a capture read back from disk, with the file it came from and that
// file's hash, so a scan can record which approved configuration it was
// measured against.
type Loaded struct {
	Capture *Capture
	File    string
	Hash    string
}

// Latest returns the newest capture recorded for host in dir, or nil when that
// computer has none. Captures are found through the ledger rather than by
// listing the folder, so a file that was never recorded is never treated as
// approved.
//
// Any error means the captures in this folder cannot be trusted and none of
// them should be compared against. Nothing in a capture file is believed before
// the ledger has vouched for it: the whole chain is verified first, and each
// file's hash is checked before any field of it is read. Otherwise editing a
// capture's host would be enough to make this walk past it, unverified, and
// treat an older capture as the approved one.
func Latest(dir, host string) (*Loaded, error) {
	entries, err := report.ReadChain(dir)
	if err != nil {
		return nil, fmt.Errorf("read capture chain: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil // nothing has been captured yet
	}
	if n, err := report.Verify(dir); err != nil {
		return nil, fmt.Errorf("capture chain broken after %d valid capture(s): %w", n, err)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		data, err := os.ReadFile(filepath.Join(dir, entries[i].File))
		if err != nil {
			return nil, fmt.Errorf("read capture %s: %w", entries[i].File, err)
		}
		sum := sha256.Sum256(data)
		if hash := hex.EncodeToString(sum[:]); hash != entries[i].Hash {
			return nil, fmt.Errorf("capture %s was modified after it was recorded", entries[i].File)
		}
		var c Capture
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("parse capture %s: %w", entries[i].File, err)
		}
		if !strings.EqualFold(c.Host, host) {
			continue
		}
		return &Loaded{Capture: &c, File: entries[i].File, Hash: entries[i].Hash}, nil
	}
	return nil, nil
}
