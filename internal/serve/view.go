package serve

import (
	"fmt"
	"html/template"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// What the pages need that the evidence does not hold directly: which badge a
// value wears, how results group under headings, what the filter chips link to,
// and the short lists the fleet page leads with. The colour of a badge only
// ever repeats what its own text already says, so none of this is load-bearing
// for a reader who cannot see the colour.

func badgeStatus(status string) string {
	switch status {
	case compare.Drift:
		return "b-drift"
	case compare.Error:
		return "b-error"
	case compare.Exception:
		return "b-exc"
	case compare.Compliant:
		return "b-ok"
	}
	return "b-mute"
}

func badgeChange(change string) string {
	switch change {
	case compare.Changed:
		return "b-chg"
	case compare.NewCheck:
		return "b-exc"
	}
	return "b-mute"
}

func badgeState(state string) string {
	switch state {
	case StateNeverScanned, StateUnreadable, StateChainBroken, StateUnverified, StateDrift:
		return "b-drift"
	case StatePartial, StateStale, StateCaptureGone:
		return "b-error"
	case StateChanged:
		return "b-chg"
	case StateClean:
		return "b-ok"
	}
	return "b-mute"
}

// kpiTone picks the accent on a count card from what the number means.
func kpiTone(n int, bad string) string {
	if n > 0 {
		return bad
	}
	return "ok"
}

// highSeverity counts the drifting checks that are high severity, which is the
// number worth leading with when the total is large.
func highSeverity(rs []compare.Result) int {
	n := 0
	for _, r := range rs {
		if r.Status == compare.Drift && strings.EqualFold(r.Severity, "high") {
			n++
		}
	}
	return n
}

// countStatus counts results with one status.
func countStatus(rs []compare.Result, status string) int {
	n := 0
	for _, r := range rs {
		if r.Status == status {
			n++
		}
	}
	return n
}

// countChanged counts results that moved since the capture.
func countChanged(rs []compare.Result) int {
	n := 0
	for _, r := range rs {
		if r.Change == compare.Changed {
			n++
		}
	}
	return n
}

// ---------- results grouped by check type ----------

// groupHeadings are the headings the results page uses, in the order the design
// puts them. Accounts and groups read as one subject, so they share a heading.
var groupHeadings = []struct {
	Title string
	Types []string
}{
	{"Firewall", []string{baseline.TypeFirewall}},
	{"Accounts & groups", []string{baseline.TypeAccount, baseline.TypeGroup}},
	{"Registry", []string{baseline.TypeRegistry}},
	{"Services", []string{baseline.TypeService}},
	{"Audit policy", []string{baseline.TypeAudit}},
	{"Software", []string{baseline.TypeSoftware}},
}

// resultGroup is one heading's worth of results.
type resultGroup struct {
	Title      string
	Rows       []compare.Result
	Drift      int
	Errors     int
	Exceptions int
	Compliant  int
	Changed    int
	Open       bool
}

// Total is how many results are under this heading.
func (g resultGroup) Total() int { return len(g.Rows) }

// groupResults sorts results under the headings above. A group opens when it
// holds something to act on, and stays shut when everything in it is fine, so
// the page opens on the problems without any script.
func groupResults(rs []compare.Result, types map[string]string) []resultGroup {
	byType := map[string][]compare.Result{}
	for _, r := range rs {
		byType[types[r.ID]] = append(byType[types[r.ID]], r)
	}

	var groups []resultGroup
	claimed := map[string]bool{}
	for _, heading := range groupHeadings {
		g := resultGroup{Title: heading.Title}
		for _, t := range heading.Types {
			claimed[t] = true
			g.Rows = append(g.Rows, byType[t]...)
		}
		if len(g.Rows) == 0 {
			continue
		}
		groups = append(groups, tally(g))
	}
	// A check the current baseline no longer lists still has results saved, and
	// hiding them would be the one thing worse than an odd heading.
	var rest []compare.Result
	for t, rows := range byType {
		if !claimed[t] {
			rest = append(rest, rows...)
		}
	}
	if len(rest) > 0 {
		sort.SliceStable(rest, func(i, j int) bool { return rest[i].ID < rest[j].ID })
		groups = append(groups, tally(resultGroup{Title: "Not in the current baseline", Rows: rest}))
	}
	return groups
}

func tally(g resultGroup) resultGroup {
	for _, r := range g.Rows {
		switch r.Status {
		case compare.Drift:
			g.Drift++
		case compare.Error:
			g.Errors++
		case compare.Exception:
			g.Exceptions++
		case compare.Compliant:
			g.Compliant++
		}
		if r.Change == compare.Changed {
			g.Changed++
		}
	}
	g.Open = g.Drift+g.Errors+g.Changed > 0
	return g
}

// ---------- filter chips ----------

// chip is one filter link. Filters are links, not a form, so narrowing the
// table needs no script and the address bar says what is being shown.
type chip struct {
	Label string
	Count int
	URL   template.URL
	On    bool
	Show  bool // whether to print the count beside the label
}

// chipSet is the chips for one page.
type chipSet struct {
	Status   []chip
	Severity []chip
}

// chips builds the filter links for one scan's results.
func chips(host, file string, f filter, rs []compare.Result) chipSet {
	link := func(status, severity, change string) template.URL {
		q := url.Values{}
		if host != "" {
			q.Set("host", host)
		}
		q.Set("file", file)
		if status != "" {
			q.Set("status", status)
		}
		if severity != "" {
			q.Set("severity", severity)
		}
		if change != "" {
			q.Set("change", change)
		}
		if f.Type != "" {
			q.Set("type", f.Type)
		}
		return template.URL("/scan?" + q.Encode())
	}

	none := f.Status == "" && f.Change == ""
	set := chipSet{
		Status: []chip{
			{Label: "All", Count: len(rs), URL: link("", f.Severity, ""), On: none, Show: true},
			{Label: "Drift", Count: countStatus(rs, compare.Drift),
				URL: link(compare.Drift, f.Severity, ""), On: f.Status == compare.Drift, Show: true},
			{Label: "Changed", Count: countChanged(rs),
				URL: link("", f.Severity, compare.Changed), On: f.Change == compare.Changed, Show: true},
			{Label: "Exception", Count: countStatus(rs, compare.Exception),
				URL: link(compare.Exception, f.Severity, ""), On: f.Status == compare.Exception, Show: true},
			{Label: "Error", Count: countStatus(rs, compare.Error),
				URL: link(compare.Error, f.Severity, ""), On: f.Status == compare.Error, Show: true},
			{Label: "Compliant", Count: countStatus(rs, compare.Compliant),
				URL: link(compare.Compliant, f.Severity, ""), On: f.Status == compare.Compliant, Show: true},
		},
		Severity: []chip{
			{Label: "Any", URL: link(f.Status, "", f.Change), On: f.Severity == ""},
			{Label: "High", URL: link(f.Status, "high", f.Change), On: f.Severity == "high"},
			{Label: "Medium", URL: link(f.Status, "medium", f.Change), On: f.Severity == "medium"},
			{Label: "Low", URL: link(f.Status, "low", f.Change), On: f.Severity == "low"},
		},
	}
	return set
}

// ---------- sparkline ----------

// sparkline draws a computer's recent drift counts as one small line, the way
// the fleet table shows it. Which way the line goes is the point, so the colour
// follows the direction: red when drift is rising, amber when the computer
// could not be read in full and the line cannot be trusted, green otherwise.
// The same numbers are in the table beside it, in full.
func sparkline(scans []*savedScan, unknown bool) template.HTML {
	var values []int
	for _, s := range scans {
		if s.Err == "" {
			values = append(values, s.Scan.Summary.Drift)
		}
	}
	if len(values) == 0 {
		return ""
	}
	if len(values) > 6 {
		values = values[len(values)-6:]
	}
	if len(values) == 1 {
		values = append(values, values[0])
	}

	max := 0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		max = 1
	}

	const w, h = 70.0, 20.0
	step := (w - 4) / float64(len(values)-1)
	points := make([]string, 0, len(values))
	for i, v := range values {
		x := 2 + float64(i)*step
		y := 18 - (float64(v)/float64(max))*14
		points = append(points, fmt.Sprintf("%.0f,%.0f", x, y))
	}

	stroke := "#1f7a33" // holding steady or improving
	switch {
	case unknown:
		stroke = "#8a5300"
	case values[len(values)-1] > values[0]:
		stroke = "#a3261e"
	}
	label := "drift per scan: " + joinInts(values)

	var out strings.Builder
	if err := sparkTemplate.Execute(&out, struct {
		Points, Stroke, Label string
	}{strings.Join(points, " "), stroke, label}); err != nil {
		return ""
	}
	return template.HTML(out.String())
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ", ")
}

// The sparkline uses presentation attributes, never a style attribute, because
// the page's content security policy allows no inline CSS.
var sparkTemplate = template.Must(template.New("spark").Parse(
	`<svg class="spark" width="70" height="20" viewBox="0 0 70 20" role="img" aria-label="{{.Label}}">` +
		`<polyline points="{{.Points}}" fill="none" stroke="{{.Stroke}}" stroke-width="2"/></svg>`))

// ---------- needs attention ----------

// attention is one line of the fleet page's short list of things to look at.
type attention struct {
	Badge string // the badge class
	Label string // the badge text
	Host  string // the computer it concerns, when it concerns one
	What  string
	Meta  string
	Link  template.URL
}

// attentionList is what the fleet page leads with: the settings that changed
// since a computer was approved, the computers that could not be read in full,
// the evidence that does not verify, and the approvals about to lapse. Most
// urgent first, in the same order the computer table uses.
func (s *Server) attentionList(computers []computer, b *baseline.Baseline, chain chainStatus) []attention {
	var out []attention

	for _, c := range computers {
		if c.Latest == nil {
			if c.Approved {
				out = append(out, attention{
					Badge: "b-drift", Label: StateNeverScanned, Host: c.Host,
					What: "has never been scanned",
					Meta: "approved in the host list, with no evidence saved yet",
				})
			}
			continue
		}
		for _, r := range changedSinceCapture(c.Latest.Scan) {
			out = append(out, attention{
				Badge: "b-chg", Label: compare.Changed, Host: c.Host,
				What: r.Title,
				Meta: fmt.Sprintf("%s · %s · %s", r.ID, strings.ToLower(r.Severity), r.Note),
				Link: computerLink(c.Key),
			})
		}
	}

	for _, c := range computers {
		if c.Latest == nil {
			continue
		}
		switch c.State() {
		case StateUnreadable:
			out = append(out, attention{
				Badge: "b-drift", Label: StateUnreadable, Host: c.Host,
				What: "answered nothing at all",
				Meta: firstNote(c.Latest.Scan), Link: computerLink(c.Key),
			})
		case StatePartial:
			out = append(out, attention{
				Badge: "b-error", Label: StatePartial, Host: c.Host,
				What: fmt.Sprintf("%d check(s) could not be read", c.Latest.Scan.Summary.Errors),
				Meta: firstNote(c.Latest.Scan), Link: computerLink(c.Key),
			})
		case StateStale:
			out = append(out, attention{
				Badge: "b-error", Label: StateStale, Host: c.Host,
				What: "has not been scanned recently",
				Meta: "last scan " + c.Since, Link: computerLink(c.Key),
			})
		}
	}

	for _, l := range chain.Ledgers {
		if l.Err != "" {
			out = append(out, attention{
				Badge: "b-drift", Label: "EVIDENCE", What: l.Kind + " ledger does not verify",
				Meta: l.Err, Link: "/verify",
			})
		}
	}

	if b != nil {
		now := s.now()
		for _, e := range b.Exceptions {
			switch exp := exceptionExpiry(e, now); exp.Label {
			case "expired":
				out = append(out, attention{
					Badge: "b-drift", Label: "EXPIRED",
					What: fmt.Sprintf("exception %s has lapsed", e.Check),
					Meta: fmt.Sprintf("approved by %s · expired %s", e.ApprovedBy, e.Expires),
					Link: "/baseline",
				})
			case "soon":
				out = append(out, attention{
					Badge: "b-exc", Label: "EXPIRING",
					What: fmt.Sprintf("exception %s expires in %d days", e.Check, exp.Days),
					Meta: fmt.Sprintf("approved by %s · %s", e.ApprovedBy, e.Expires),
					Link: "/baseline",
				})
			}
		}
	}
	return out
}

func computerLink(key string) template.URL {
	if key == "" {
		return "/computer"
	}
	return template.URL("/computer?host=" + url.QueryEscape(key))
}

// firstNote is the first thing a scan had to say about why a check failed.
func firstNote(s report.Scan) string {
	for _, r := range s.Results {
		if r.Status == compare.Error && r.Note != "" {
			return r.Note
		}
	}
	return ""
}

// ---------- baseline page ----------

// typeRow is one row of the baseline page's checks-by-type table.
type typeRow struct {
	Title  string
	Checks int
	High   int
	Medium int
	Low    int
}

// checksByType counts the baseline's checks under the same headings the results
// page groups by, so the two pages describe the policy the same way.
func checksByType(b *baseline.Baseline) []typeRow {
	if b == nil {
		return nil
	}
	var rows []typeRow
	for _, heading := range groupHeadings {
		row := typeRow{Title: heading.Title}
		for _, c := range b.Checks {
			if !hasType(heading.Types, c.Type) {
				continue
			}
			row.Checks++
			switch strings.ToLower(c.Severity) {
			case "high":
				row.High++
			case "medium":
				row.Medium++
			case "low":
				row.Low++
			}
		}
		if row.Checks > 0 {
			rows = append(rows, row)
		}
	}
	return rows
}

func hasType(types []string, t string) bool {
	for _, want := range types {
		if want == t {
			return true
		}
	}
	return false
}

// ---------- what a setting was, and is ----------

// changedRow is one setting that moved since the capture, with the two values
// side by side.
type changedRow struct {
	compare.Result
	Was string
	Now string
}

// changedRows lists what moved since the capture, newest problems first.
func changedRows(s report.Scan) []changedRow {
	var out []changedRow
	for _, r := range changedSinceCapture(s) {
		was, now := wasNow(r)
		out = append(out, changedRow{Result: r, Was: was, Now: now})
	}
	return out
}

// wasNow pulls the two values out of the note ApplyChange writes, which is the
// only place a saved scan records what a setting used to be: the captured value
// is not otherwise in the scan. The format is this program's own, so when it
// does not match, the row falls back to what the check expected and what it
// found, which is never wrong, only less specific.
func wasNow(r compare.Result) (string, string) {
	const marker = "changed since capture: was "
	i := strings.Index(r.Note, marker)
	if i < 0 {
		return r.Expected, r.Actual
	}
	was, rest, ok := nextQuoted(r.Note[i+len(marker):])
	if !ok {
		return r.Expected, r.Actual
	}
	now, _, ok := nextQuoted(rest)
	if !ok {
		return r.Expected, r.Actual
	}
	return was, now
}

// nextQuoted reads the next Go-quoted string out of s.
func nextQuoted(s string) (value, rest string, ok bool) {
	start := strings.IndexByte(s, '"')
	if start < 0 {
		return "", "", false
	}
	for i := start + 1; i < len(s); i++ {
		if s[i] == 0x5c { // a backslash escapes the next byte
			i++
			continue
		}
		if s[i] == '"' {
			v, err := strconv.Unquote(s[start : i+1])
			if err != nil {
				return "", "", false
			}
			return v, s[i+1:], true
		}
	}
	return "", "", false
}
