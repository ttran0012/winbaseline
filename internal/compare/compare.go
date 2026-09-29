// Package compare evaluates observed values against baseline checks.
package compare

import (
	"fmt"

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
	res := Result{
		ID:       c.ID,
		Title:    c.Title,
		Severity: c.Severity,
		Location: fmt.Sprintf(`%s\%s\%s`, c.Hive, c.Path, c.Value),
		Expected: describe(c.Operator, c.Expected),
	}

	if r.Err != nil {
		res.Status, res.Actual, res.Note = Error, "unreadable", r.Err.Error()
		return res
	}

	actual := r.Value
	switch {
	case r.Present:
		res.Actual = fmt.Sprint(actual)
	case c.Default != nil:
		actual = *c.Default
		res.Actual = fmt.Sprintf("not set (Windows default %d)", actual)
	default:
		res.Status, res.Actual, res.Note = Drift, "not set", "setting is not configured"
		return res
	}

	if matches(c.Operator, actual, c.Expected) {
		res.Status = Compliant
	} else {
		res.Status = Drift
	}
	return res
}

func matches(op string, actual, expected uint64) bool {
	switch op {
	case "lte":
		return actual <= expected
	case "gte":
		return actual >= expected
	default:
		return actual == expected
	}
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
