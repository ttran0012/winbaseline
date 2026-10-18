package report

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ttran0012/winbaseline/internal/compare"
)

// The HTML report is a readable view of one saved scan: a single self-contained
// file with no scripts, no links, and no external fonts, so it can be emailed
// or attached to an audit folder unchanged. The JSON file remains the record of
// record; the HTML is never part of the hash chain.

// statusOrder lists results that need action before those that do not.
var statusOrder = map[string]int{
	compare.Drift:     0,
	compare.Error:     1,
	compare.Exception: 2,
	compare.Compliant: 3,
}

// severityOrder lists the most severe check first.
var severityOrder = map[string]int{"high": 0, "medium": 1, "low": 2}

// changeRank puts settings that no longer match the approved capture above
// everything else, because a change nobody approved is the first thing the
// person reading the report needs to see. Scans without a capture have no
// change at all, so this leaves their order to the status rules below.
func changeRank(change string) int {
	if change == compare.Changed {
		return 0
	}
	return 1
}

// rank returns the position of key, or one past the end for anything unlisted,
// so an unexpected value sorts last instead of first.
func rank(order map[string]int, key string) int {
	if i, ok := order[strings.ToLower(key)]; ok {
		return i
	}
	if i, ok := order[strings.ToUpper(key)]; ok {
		return i
	}
	return len(order)
}

// sortForReport copies the results into reading order: anything changed since
// the capture first, then drift, errors, approved exceptions, and compliant
// checks, each group most severe first. The saved JSON keeps the baseline's own
// order, so the hashed evidence is untouched.
func sortForReport(rs []compare.Result) []compare.Result {
	out := make([]compare.Result, len(rs))
	copy(out, rs)
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := changeRank(out[i].Change), changeRank(out[j].Change); a != b {
			return a < b
		}
		if a, b := rank(statusOrder, out[i].Status), rank(statusOrder, out[j].Status); a != b {
			return a < b
		}
		return rank(severityOrder, out[i].Severity) < rank(severityOrder, out[j].Severity)
	})
	return out
}

// statusClass and severityClass map a value to a known CSS class, so an
// unexpected status cannot become part of the page's markup.
func statusClass(status string) string {
	switch status {
	case compare.Drift:
		return "drift"
	case compare.Error:
		return "error"
	case compare.Exception:
		return "exception"
	case compare.Compliant:
		return "compliant"
	}
	return "other"
}

func severityClass(severity string) string {
	switch strings.ToLower(severity) {
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	}
	return "other"
}

func changeClass(change string) string {
	switch change {
	case compare.Changed:
		return "changed"
	case compare.Unchanged:
		return "unchanged"
	case compare.NewCheck:
		return "new-check"
	}
	return "other"
}

type htmlData struct {
	Scan     Scan
	Results  []compare.Result // sorted for reading; Scan.Results keeps the saved order
	Evidence ChainEntry
}

// WriteHTML renders the scan as a self-contained HTML page. Every value comes
// from the system being scanned, so all of it is escaped by html/template.
func WriteHTML(w io.Writer, s Scan, e ChainEntry) error {
	return htmlTemplate.Execute(w, htmlData{Scan: s, Results: sortForReport(s.Results), Evidence: e})
}

// SaveHTML writes the HTML view next to the JSON evidence file it describes,
// with the same base name, and returns its path.
func SaveHTML(dir string, s Scan, e ChainEntry) (string, error) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, s, e); err != nil {
		return "", fmt.Errorf("render HTML report: %w", err)
	}
	path := filepath.Join(dir, strings.TrimSuffix(e.File, ".json")+".html")
	if err := WriteNew(path, buf.Bytes()); err != nil {
		return "", fmt.Errorf("write HTML report: %w", err)
	}
	return path, nil
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"statusClass":   statusClass,
	"severityClass": severityClass,
	"changeClass":   changeClass,
	"upper":         strings.ToUpper,
}).Parse(htmlSource))

// htmlSource is the whole page: inline styles only, no scripts, no links, and
// no web fonts, so the saved file renders the same offline and when attached to
// an email. Status is always spelled out as well as colored, so the report is
// still readable printed in black and white.
const htmlSource = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Configuration drift report - {{.Scan.Host}}</title>
<style>
  body { font-family: "Segoe UI", Tahoma, Arial, sans-serif; color: #1a1a1a; background: #fff;
         margin: 0; padding: 24px; font-size: 14px; line-height: 1.45; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 15px; margin: 28px 0 8px; text-transform: uppercase; letter-spacing: .04em; color: #444; }
  .sub { color: #555; margin: 0 0 20px; }
  dl.facts { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0; }
  dl.facts dt { color: #555; }
  dl.facts dd { margin: 0; font-weight: 600; }
  ul.counts { list-style: none; display: flex; flex-wrap: wrap; gap: 10px; margin: 0; padding: 0; }
  ul.counts li { border: 1px solid #bbb; border-left-width: 5px; border-radius: 3px;
                 padding: 8px 14px; min-width: 92px; }
  ul.counts .n { display: block; font-size: 20px; font-weight: 700; }
  ul.counts .k { color: #444; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  table { border-collapse: collapse; width: 100%; margin-top: 4px; }
  th, td { border: 1px solid #ccc; padding: 6px 8px; text-align: left; vertical-align: top;
           word-break: break-word; }
  th { background: #f0f0f0; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
  tbody tr:nth-child(even) { background: #fafafa; }
  td.id { font-family: Consolas, "Courier New", monospace; white-space: nowrap; }
  td.setting .where { display: block; color: #555; font-size: 12px;
                      font-family: Consolas, "Courier New", monospace; }
  .badge { display: inline-block; border: 1px solid #555; border-radius: 3px; padding: 1px 6px;
           font-size: 12px; font-weight: 700; white-space: nowrap; }
  .drift      { background: #fdecea; border-color: #a3261e; color: #7c1d16; }
  .error      { background: #fff4e5; border-color: #9a5b00; color: #7a4800; }
  .exception  { background: #eaf1fb; border-color: #1a4f9c; color: #14407e; }
  .compliant  { background: #eaf6ec; border-color: #1f7a33; color: #19622a; }
  .other      { background: #f0f0f0; border-color: #555; color: #333; }
  .changed    { background: #f4eafd; border-color: #67399e; color: #4e2a79; }
  .unchanged  { background: #fff; border-color: #bbb; color: #555; font-weight: 400; }
  .new-check  { background: #e9f4f4; border-color: #19616b; color: #134e56; }
  li.drift, li.error, li.exception, li.compliant, li.changed, li.total { background: #fff; }
  li.total { border-left-color: #555; }
  li.drift { border-left-color: #a3261e; }
  li.error { border-left-color: #9a5b00; }
  li.exception { border-left-color: #1a4f9c; }
  li.compliant { border-left-color: #1f7a33; }
  li.changed { border-left-color: #67399e; }
  p.alert { border: 2px solid #a3261e; border-left-width: 8px; background: #fdecea; color: #7c1d16;
            padding: 10px 14px; margin: 0 0 20px; border-radius: 3px; }
  p.alert strong { text-transform: uppercase; letter-spacing: .03em; }
  .sev { font-size: 12px; font-weight: 600; white-space: nowrap; }
  .sev.high { color: #7c1d16; }
  .sev.medium { color: #7a4800; }
  .sev.low { color: #444; }
  .note { color: #333; font-size: 13px; }
  footer { margin-top: 28px; border-top: 1px solid #ccc; padding-top: 12px;
           color: #444; font-size: 12px; }
  footer dl { display: grid; grid-template-columns: max-content 1fr; gap: 2px 12px; margin: 0 0 8px; }
  footer dt { color: #555; }
  footer dd { margin: 0; font-family: Consolas, "Courier New", monospace; word-break: break-all; }
</style>
</head>
<body>

<h1>Windows configuration drift report</h1>
<p class="sub">Read-only scan. No setting on this computer was changed.</p>

{{if .Scan.CaptureStatus}}<p class="alert"><strong>Capture not used</strong> &mdash; {{.Scan.CaptureStatus}}.
The policy results below ran as usual, but this scan says nothing about what changed since this
computer was approved. Verify the capture chain before relying on the change history.</p>{{end}}

<dl class="facts">
  <dt>Computer</dt><dd>{{.Scan.Host}}</dd>
  <dt>Scan time</dt><dd>{{.Scan.StartedAt.Format "Mon, 02 Jan 2006 15:04:05 MST"}}</dd>
  <dt>Baseline</dt><dd>{{.Scan.BaselineName}} v{{.Scan.BaselineVersion}}</dd>
  <dt>Ran as administrator</dt><dd>{{if .Scan.Elevated}}Yes{{else}}No - some settings could not be read{{end}}</dd>
  {{with .Scan.Capture}}<dt>Approved capture</dt><dd>{{.CapturedAt.Format "Mon, 02 Jan 2006 15:04:05 MST"}}</dd>{{end}}
</dl>

<h2>Summary</h2>
<ul class="counts">
  <li class="total"><span class="n">{{.Scan.Summary.Total}}</span><span class="k">Checks</span></li>
  <li class="compliant"><span class="n">{{.Scan.Summary.Compliant}}</span><span class="k">Compliant</span></li>
  <li class="drift"><span class="n">{{.Scan.Summary.Drift}}</span><span class="k">Drift</span></li>
  {{if .Scan.Summary.Exceptions}}<li class="exception"><span class="n">{{.Scan.Summary.Exceptions}}</span><span class="k">Exceptions</span></li>{{end}}
  <li class="error"><span class="n">{{.Scan.Summary.Errors}}</span><span class="k">Errors</span></li>
  {{if .Scan.Capture}}<li class="changed"><span class="n">{{.Scan.Summary.Changed}}</span><span class="k">Changed</span></li>{{end}}
</ul>

<h2>Results</h2>
<table>
<thead>
<tr><th>ID</th><th>Status</th>{{if .Scan.Capture}}<th>Change</th>{{end}}<th>Severity</th><th>Setting</th><th>Expected</th><th>Actual</th><th>Note</th></tr>
</thead>
<tbody>
{{range .Results}}
<tr>
  <td class="id">{{.ID}}</td>
  <td><span class="badge {{statusClass .Status}}">{{.Status}}</span></td>
  {{if $.Scan.Capture}}<td><span class="badge {{changeClass .Change}}">{{.Change}}</span></td>{{end}}
  <td><span class="sev {{severityClass .Severity}}">{{upper .Severity}}</span></td>
  <td class="setting">{{.Title}}{{if .Location}}<span class="where">{{.Location}}</span>{{end}}</td>
  <td>{{.Expected}}</td>
  <td>{{.Actual}}</td>
  <td class="note">{{.Note}}</td>
</tr>
{{else}}
<tr><td colspan="{{if .Scan.Capture}}8{{else}}7{{end}}">This scan recorded no results.</td></tr>
{{end}}
</tbody>
</table>

<footer>
<dl>
  <dt>Evidence file</dt><dd>{{.Evidence.File}}</dd>
  <dt>SHA-256</dt><dd>{{.Evidence.Hash}}</dd>
  <dt>Previous scan</dt><dd>{{.Evidence.PreviousHash}}</dd>
{{with .Scan.Capture}}  <dt>Capture file</dt><dd>{{.File}}</dd>
  <dt>Capture SHA-256</dt><dd>{{.Hash}}</dd>
{{end}}</dl>
<p>The JSON evidence file named above is the tamper-evident record of this scan, hash-chained
to the scan before it; this page is only a readable view of that file and is not part of the chain.</p>
</footer>

</body>
</html>
`
