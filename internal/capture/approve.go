package capture

import (
	"fmt"
	"time"

	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// An approval is a capture made from a scan a person reviewed, rather than from
// a fresh reading of the computer. -capture records what a computer looks like
// right now; approving a scan records what someone looked at and signed off,
// naming the exact saved scan it was built from so the decision can be audited
// later. Both produce the same kind of capture, so everything downstream - the
// chain, Latest, the change comparison - treats them alike.

// Approval is the record of who signed a scan off as the baseline, kept on the
// capture it produced. A capture made by -capture has no Approval.
type Approval struct {
	ApprovedBy     string    `json:"approved_by"`
	ApprovedAt     time.Time `json:"approved_at"`
	Note           string    `json:"note"`
	SourceScan     string    `json:"source_scan"` // the scan file this was built from
	SourceHash     string    `json:"source_hash"` // that file's SHA-256, as the ledger recorded it
	ExcludedChecks []string  `json:"excluded_checks,omitempty"`
}

// ApproveOptions are the facts an approval records. ExcludeErrors has to be set
// when the scan has unreadable checks: "unreadable" must never be recorded as
// the approved configuration, so those checks are dropped and listed, and
// FromScan refuses if they are present and this is not set.
type ApproveOptions struct {
	ApprovedBy    string
	At            time.Time
	Note          string
	SourceFile    string
	SourceHash    string
	ExcludeErrors bool
}

// ErrReviewRequired is returned when an approval arrives with no note.
var ErrReviewRequired = fmt.Errorf("an approval needs a note saying what was reviewed")

// FromScan builds a capture from a scan a person reviewed, using the normalized
// value already stored on each result. It refuses an approval that records
// nothing meaningful: a scan saved before normalized values existed, an
// approval with no note, or a scan with unreadable checks that were not
// explicitly excluded. ERROR checks are never recorded as entries - approving
// "unreadable" as the configuration is exactly the mistake -capture's
// administrator check guards against - so they are listed as excluded instead.
func FromScan(s report.Scan, o ApproveOptions) (*Capture, error) {
	if o.Note == "" {
		return nil, ErrReviewRequired
	}

	var errorIDs []string
	for _, r := range s.Results {
		if r.Status == compare.Error {
			errorIDs = append(errorIDs, r.ID)
		}
	}
	if len(errorIDs) > 0 && !o.ExcludeErrors {
		return nil, fmt.Errorf("this scan has %d unreadable check(s) (%s); approve it only after "+
			"confirming they are left out, so \"unreadable\" is not recorded as the approved configuration",
			len(errorIDs), joinIDs(errorIDs))
	}

	c := &Capture{
		Host:            s.Host,
		CapturedAt:      o.At,
		CapturedBy:      o.ApprovedBy,
		BaselineName:    s.BaselineName,
		BaselineVersion: s.BaselineVersion,
		Approval: &Approval{
			ApprovedBy:     o.ApprovedBy,
			ApprovedAt:     o.At,
			Note:           o.Note,
			SourceScan:     o.SourceFile,
			SourceHash:     o.SourceHash,
			ExcludedChecks: errorIDs,
		},
	}
	for _, r := range s.Results {
		if r.Status == compare.Error {
			continue // excluded: recorded in Approval.ExcludedChecks, never as a value
		}
		if r.Normalized == "" {
			return nil, fmt.Errorf("check %s has no normalized value: this scan was saved before "+
				"approval was supported, so re-scan the computer and approve the new scan", r.ID)
		}
		c.Entries = append(c.Entries, Entry{ID: r.ID, Value: r.Normalized, Status: r.Status})
	}
	if len(c.Entries) == 0 {
		return nil, fmt.Errorf("nothing readable to approve: every check in this scan was unreadable")
	}
	return c, nil
}

// joinIDs lists check IDs for a message without pulling in strings.Join at the
// cost of a comma-space it would add anyway.
func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ", "
		}
		out += id
	}
	return out
}
