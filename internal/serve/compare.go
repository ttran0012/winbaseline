package serve

import (
	"sort"

	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// difference is one check that does not read the same way in both scans.
type difference struct {
	ID         string
	Title      string
	Severity   string
	FromStatus string
	ToStatus   string
	FromActual string
	ToActual   string
}

// comparison is the difference between two scans, grouped by what happened.
// Every check belongs to exactly one group, so the groups add up and nothing is
// counted twice.
type comparison struct {
	NewDrift   []difference // was not drifting, now is
	Fixed      []difference // was drifting, now is not
	StillDrift []difference // drifting in both
	Changed    []difference // not drifting either time, but the value moved
	OnlyInOne  []difference // the baseline gained or lost the check in between
}

// Total is how many checks differ at all.
func (c comparison) Total() int {
	return len(c.NewDrift) + len(c.Fixed) + len(c.StillDrift) + len(c.Changed) + len(c.OnlyInOne)
}

// group is one named set of differences as the compare page lists it.
type group struct {
	Title string
	Note  string
	Rows  []difference
}

// Groups returns the comparison in reading order: what got worse, then what got
// better, then what stayed bad, then the quieter movements.
func (c comparison) Groups() []group {
	return []group{
		{"New drift", "Met the policy in the earlier scan, does not in the later one.", c.NewDrift},
		{"Fixed", "Did not meet the policy in the earlier scan, meets it now.", c.Fixed},
		{"Still drifting", "Did not meet the policy either time. An approved exception counts as a deviation, so a check that was approved in between is listed here rather than as fixed.", c.StillDrift},
		{"Changed values", "The value or the status moved without crossing between drifting and not drifting, including checks that became unreadable.", c.Changed},
		{"Only in one scan", "The baseline gained or lost the check between the two scans.", c.OnlyInOne},
	}
}

// compareScans sorts the checks of two scans into the groups above. Drift is
// the thing being tracked, so it decides the group first; a check that is
// drifting in both is still worth listing, because its value may have moved
// again underneath.
func compareScans(from, to report.Scan) comparison {
	fromByID := byID(from.Results)
	toByID := byID(to.Results)

	var c comparison
	for _, t := range to.Results {
		f, inBoth := fromByID[t.ID]
		if !inBoth {
			c.OnlyInOne = append(c.OnlyInOne, difference{
				ID: t.ID, Title: t.Title, Severity: t.Severity,
				FromStatus: "not in this scan", ToStatus: t.Status, ToActual: t.Actual,
			})
			continue
		}
		d := difference{
			ID: t.ID, Title: t.Title, Severity: t.Severity,
			FromStatus: f.Status, ToStatus: t.Status,
			FromActual: f.Actual, ToActual: t.Actual,
		}
		switch {
		case f.Status == compare.Error || t.Status == compare.Error:
			// A check nobody could read either time cannot be called fixed or
			// newly broken; saying so would be inventing a finding.
			if f.Status != t.Status || f.Actual != t.Actual {
				c.Changed = append(c.Changed, d)
			}
		case !deviating(f.Status) && deviating(t.Status):
			c.NewDrift = append(c.NewDrift, d)
		case deviating(f.Status) && !deviating(t.Status):
			c.Fixed = append(c.Fixed, d)
		case deviating(f.Status) && deviating(t.Status):
			c.StillDrift = append(c.StillDrift, d)
		case f.Actual != t.Actual || f.Status != t.Status:
			c.Changed = append(c.Changed, d)
		}
	}
	// A check the later scan does not have at all was dropped from the baseline.
	for _, f := range from.Results {
		if _, ok := toByID[f.ID]; !ok {
			c.OnlyInOne = append(c.OnlyInOne, difference{
				ID: f.ID, Title: f.Title, Severity: f.Severity,
				FromStatus: f.Status, FromActual: f.Actual, ToStatus: "not in this scan",
			})
		}
	}

	for _, group := range [][]difference{c.NewDrift, c.Fixed, c.StillDrift, c.Changed, c.OnlyInOne} {
		sortDifferences(group)
	}
	return c
}

// deviating reports whether the check was not meeting the policy, approved or
// not. An approved exception is still a deviation; it is one somebody signed
// for, which is why a check that goes from drift to exception is listed as
// still drifting rather than fixed.
func deviating(status string) bool {
	return status == compare.Drift || status == compare.Exception
}

func byID(rs []compare.Result) map[string]compare.Result {
	m := make(map[string]compare.Result, len(rs))
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

// sortDifferences puts the most severe first, as the report does, and falls
// back to the check ID so the order never wobbles between page loads.
func sortDifferences(ds []difference) {
	severity := map[string]int{"high": 0, "medium": 1, "low": 2}
	rank := func(s string) int {
		if i, ok := severity[s]; ok {
			return i
		}
		return len(severity)
	}
	sort.SliceStable(ds, func(i, j int) bool {
		if a, b := rank(ds[i].Severity), rank(ds[j].Severity); a != b {
			return a < b
		}
		return ds[i].ID < ds[j].ID
	})
}

// newDrift lists the checks that are drifting in the later scan and were not in
// the earlier one. The overview uses it for computers that have no capture to
// compare against.
func newDrift(from, to report.Scan) []compare.Result {
	fromByID := byID(from.Results)
	var out []compare.Result
	for _, t := range to.Results {
		if t.Status != compare.Drift {
			continue
		}
		if f, ok := fromByID[t.ID]; ok && f.Status == compare.Drift {
			continue
		}
		out = append(out, t)
	}
	return report.SortForReport(out)
}

// changedSinceCapture lists what the scan found no longer matching the
// configuration this computer was approved with.
func changedSinceCapture(s report.Scan) []compare.Result {
	var out []compare.Result
	for _, r := range s.Results {
		if r.Change == compare.Changed {
			out = append(out, r)
		}
	}
	return report.SortForReport(out)
}
