// Package compare evaluates observed values against baseline checks.
package compare

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
)

// Status of a single check.
const (
	Compliant = "COMPLIANT"
	Drift     = "DRIFT"
	Error     = "ERROR"
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
