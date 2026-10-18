// Package compare evaluates observed values against baseline checks.
package compare

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
)

// Status of a single check: how the setting compares with the baseline policy.
const (
	Compliant = "COMPLIANT"
	Drift     = "DRIFT"
	Exception = "EXCEPTION"
	Error     = "ERROR"
)

// Change of a single check: how the setting compares with the configuration
// that was captured and approved for this computer. It answers a different
// question from Status, which is why it is reported beside it: a setting can be
// compliant with the baseline and still have been changed since it was
// approved, or be drifting and have been drifting ever since the capture.
const (
	Unchanged = "UNCHANGED"
	Changed   = "CHANGED"
	NewCheck  = "NEW_CHECK"
)

// Result is the outcome of one check.
type Result struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Location string `json:"location"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Status   string `json:"status"`
	Change   string `json:"change,omitempty"` // empty unless the scan was compared with a capture
	Note     string `json:"note,omitempty"`
}

// Evaluate compares one reading with its check.
func Evaluate(c baseline.Check, r collect.Reading) Result {
	res := Result{ID: c.ID, Title: c.Title, Severity: c.Severity, Location: c.Location()}
	if r.Err != nil {
		res.Expected = strings.ReplaceAll(c.Expected, "_", " ")
		res.Status, res.Actual, res.Note = Error, "unreadable", r.Err.Error()
		return res
	}
	var ok bool
	switch c.Type {
	case baseline.TypeRegistry:
		ok = evalRegistry(c, r, &res)
	case baseline.TypeService:
		ok = evalService(c, r, &res)
	case baseline.TypeAccount:
		ok = evalAccount(c, r, &res)
	case baseline.TypeGroup:
		ok = evalGroup(c, r, &res)
	case baseline.TypeFirewall:
		ok = evalFirewall(r, &res)
	case baseline.TypeAudit:
		ok = evalAudit(c, r, &res)
	case baseline.TypeSoftware:
		ok = evalSoftware(r, &res)
	default:
		res.Status, res.Note = Error, "unsupported check type"
		return res
	}
	if res.Status == "" {
		res.Status = Drift
		if ok {
			res.Status = Compliant
		}
	}
	return res
}

// ApplyExceptions reports an approved deviation as EXCEPTION instead of DRIFT.
// An exception applies only to a drift result, only on a host it covers, and
// only up to and including its expiry date; today is passed in so the decision
// is reproducible. Compliant and error results are returned unchanged.
func ApplyExceptions(res Result, exceptions []baseline.Exception, host string, today time.Time) Result {
	if res.Status != Drift {
		return res
	}
	var expired baseline.Exception
	var foundExpired bool
	for _, e := range exceptions {
		if !e.Covers(res.ID, host) {
			continue
		}
		expiry, err := e.ExpiresOn() // validated when the baseline loaded
		if err != nil {
			continue
		}
		if !onOrBefore(today, expiry) {
			if !foundExpired {
				expired, foundExpired = e, true
			}
			continue
		}
		res.Status = Exception
		res.Note = addNote(res.Note, fmt.Sprintf("approved exception: %s (approved by %s, expires %s)",
			e.Reason, e.ApprovedBy, e.Expires))
		return res
	}
	if foundExpired {
		res.Note = addNote(res.Note, fmt.Sprintf("approved exception expired on %s: %s (approved by %s)",
			expired.Expires, expired.Reason, expired.ApprovedBy))
	}
	return res
}

// ApplyChange records how the setting compares with the approved capture.
// Both values are normalized captures of the same reading, so they can be
// compared as plain text: approved is the value recorded in the capture and
// current is the value read now. inCapture is false when the capture was taken
// before the check existed, which is reported as a new check rather than as a
// change nobody approved. Scans run without a capture never call this, and
// their results carry no change at all.
func ApplyChange(res Result, approved, current string, inCapture bool) Result {
	switch {
	case !inCapture:
		res.Change = NewCheck
	case approved == current:
		res.Change = Unchanged
	default:
		res.Change = Changed
		// Quoted, because a captured value can itself be a comma-separated list.
		res.Note = addNote(res.Note, fmt.Sprintf("changed since capture: was %q, now %q", approved, current))
	}
	return res
}

// onOrBefore compares calendar days, so an exception still applies for the whole
// of its expiry date whatever time of day the scan runs.
func onOrBefore(today, expiry time.Time) bool {
	y, m, d := today.Date()
	return !time.Date(y, m, d, 0, 0, 0, 0, time.UTC).After(expiry)
}

// addNote keeps the note the check already produced and adds another.
func addNote(existing, note string) string {
	if existing == "" {
		return note
	}
	return existing + "; " + note
}

func evalRegistry(c baseline.Check, r collect.Reading, res *Result) bool {
	expected, _ := strconv.ParseUint(c.Expected, 10, 64) // validated when the baseline loaded
	res.Expected = describe(c.Operator, expected)
	actual := r.Num
	switch {
	case r.Present:
		res.Actual = fmt.Sprint(actual)
	case c.Default != nil:
		actual = *c.Default
		res.Actual = fmt.Sprintf("not set (Windows default %d)", actual)
	default:
		res.Actual, res.Note = "not set", "setting is not configured"
		return false
	}
	switch c.Operator {
	case "lte":
		return actual <= expected
	case "gte":
		return actual >= expected
	default:
		return actual == expected
	}
}

func evalService(c baseline.Check, r collect.Reading, res *Result) bool {
	res.Expected = strings.ReplaceAll(c.Expected, "_", " ")
	if !r.Present {
		res.Actual = "not installed"
		return c.Expected == "disabled_or_absent"
	}
	res.Actual = r.Text
	return r.Num == 4 // SERVICE_DISABLED
}

func evalAccount(c baseline.Check, r collect.Reading, res *Result) bool {
	res.Expected = c.Expected
	if !r.Present {
		res.Actual = "account not found"
		return c.Expected == "disabled" // a missing account cannot be used
	}
	disabled := r.Num == 1
	state := "enabled"
	if disabled {
		state = "disabled"
	}
	res.Actual = fmt.Sprintf("%s (named %q)", state, r.Text)
	if c.Expected == "renamed" {
		return !strings.EqualFold(r.Text, "Administrator")
	}
	return disabled
}

func evalGroup(c baseline.Check, r collect.Reading, res *Result) bool {
	res.Expected = "only: " + strings.Join(c.Approved, ", ")
	var unapproved []string
	for _, m := range r.List {
		if !approvedMember(m, c.Approved) {
			unapproved = append(unapproved, m)
		}
	}
	res.Actual = strings.Join(r.List, ", ")
	if len(unapproved) > 0 {
		res.Note = "unapproved members: " + strings.Join(unapproved, ", ")
		return false
	}
	return true
}

// approvedMember matches "COMPUTER\name" against approved entries written as
// either the full name or just the account name.
func approvedMember(member string, approved []string) bool {
	short := member
	if i := strings.LastIndex(member, `\`); i >= 0 {
		short = member[i+1:]
	}
	for _, a := range approved {
		if strings.EqualFold(a, member) || strings.EqualFold(a, short) {
			return true
		}
	}
	return false
}

func evalFirewall(r collect.Reading, res *Result) bool {
	res.Expected = "on"
	if !r.Present {
		res.Actual, res.Note = "not set", "firewall state not found"
		return false
	}
	state := "off"
	if r.Num == 1 {
		state = "on"
	}
	res.Actual = fmt.Sprintf("%s (%s)", state, r.Text)
	return r.Num == 1
}

func evalAudit(c baseline.Check, r collect.Reading, res *Result) bool {
	res.Expected = strings.ReplaceAll(c.Expected, "_", " ")
	if !r.Present {
		res.Actual, res.Note = "not found", "subcategory not reported by auditpol"
		return false
	}
	res.Actual = r.Text
	// Match the English words; auditpol reports the setting in English on English systems.
	// The subcategory itself is matched by GUID, so it works on any language.
	setting := strings.ToLower(r.Text)
	hasSuccess := strings.Contains(setting, "success")
	hasFailure := strings.Contains(setting, "failure")
	switch c.Expected {
	case "success":
		return hasSuccess
	case "failure":
		return hasFailure
	default:
		return hasSuccess && hasFailure
	}
}

func evalSoftware(r collect.Reading, res *Result) bool {
	res.Expected = "not installed"
	if len(r.List) == 0 {
		res.Actual = "not installed"
		return true
	}
	res.Actual = strings.Join(r.List, ", ")
	return false
}

func describe(op string, v uint64) string {
	switch op {
	case "lte":
		return fmt.Sprintf("<= %d", v)
	case "gte":
		return fmt.Sprintf(">= %d", v)
	default:
		return fmt.Sprint(v)
	}
}
