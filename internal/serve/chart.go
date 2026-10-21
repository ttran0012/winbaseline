package serve

import (
	"html/template"
	"strconv"
	"strings"
)

// The drift trend is drawn here, in Go, as an SVG the page carries inline. A
// chart library would mean a script, and the dashboard sends no scripts; an
// image file would mean generating and storing one. Drawing it is also the only
// way to keep the promise that the chart is readable without color: every bar
// carries its number, and the same numbers are in the table on the scans page.

// trendBars is how many scans the chart shows. Older scans are still listed on
// the scans page; the chart is for the recent shape of things.
const trendBars = 30

// bar is one scan in the chart.
type bar struct {
	X, Y, W, H int
	Drift      int
	Label      string // the date, written under some of the bars
	Title      string // the whole story, for a tooltip and for screen readers
}

// chart is everything the SVG template needs.
type chart struct {
	Width, Height int
	PlotBottom    int
	Bars          []bar
	Max           int
	Scans         int
	Desc          string
}

// trendChart draws the drift count of each scan as a bar chart.
func trendChart(scans []*savedScan) template.HTML {
	readable := make([]*savedScan, 0, len(scans))
	for _, s := range scans {
		if s.Err == "" {
			readable = append(readable, s)
		}
	}
	if len(readable) == 0 {
		return ""
	}
	if len(readable) > trendBars {
		readable = readable[len(readable)-trendBars:]
	}

	const (
		barW, gap    = 18, 8
		left, right  = 44, 12
		top, bottomH = 18, 34
		plotH        = 130
	)
	c := chart{
		Height:     top + plotH + bottomH,
		PlotBottom: top + plotH,
		Width:      left + len(readable)*(barW+gap) + right,
		Scans:      len(readable),
	}
	for _, s := range readable {
		if d := s.Scan.Summary.Drift; d > c.Max {
			c.Max = d
		}
	}
	scale := c.Max
	if scale == 0 {
		scale = 1 // an all-clear run still needs a baseline to draw against
	}

	for i, s := range readable {
		drift := s.Scan.Summary.Drift
		h := drift * plotH / scale
		if drift > 0 && h < 2 {
			h = 2 // one drifting check must not disappear into the axis
		}
		label := ""
		// Label the ends and every fifth bar, so the dates stay legible.
		if i == 0 || i == len(readable)-1 || i%5 == 0 {
			label = s.Scan.StartedAt.Format("02 Jan")
		}
		c.Bars = append(c.Bars, bar{
			X:     left + i*(barW+gap),
			Y:     c.PlotBottom - h,
			W:     barW,
			H:     h,
			Drift: drift,
			Label: label,
			Title: s.Scan.StartedAt.Format("2006-01-02 15:04") + ": " + plural(drift, "drifting check"),
		})
	}
	c.Desc = "Drifting checks in the last " + plural(len(readable), "scan") +
		", oldest on the left, highest " + plural(c.Max, "drifting check") + "."

	var out strings.Builder
	if err := chartTemplate.Execute(&out, c); err != nil {
		return "" // the chart is decoration; the counts are on the page regardless
	}
	return template.HTML(out.String())
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// The SVG uses presentation attributes rather than style attributes, because
// the page's content security policy allows no inline CSS.
var chartTemplate = template.Must(template.New("chart").Parse(`<svg class="trend" role="img" width="{{.Width}}" height="{{.Height}}"
     viewBox="0 0 {{.Width}} {{.Height}}" xmlns="http://www.w3.org/2000/svg">
  <title>Drift trend</title>
  <desc>{{.Desc}}</desc>
  <line x1="40" y1="{{.PlotBottom}}" x2="{{.Width}}" y2="{{.PlotBottom}}" stroke="#999" stroke-width="1"/>
  <text x="36" y="{{.PlotBottom}}" text-anchor="end" font-size="10" fill="#555">0</text>
  <text x="36" y="26" text-anchor="end" font-size="10" fill="#555">{{.Max}}</text>
{{range .Bars}}  <g>
    <title>{{.Title}}</title>
    <rect x="{{.X}}" y="{{.Y}}" width="{{.W}}" height="{{.H}}" fill="#fdecea" stroke="#a3261e" stroke-width="1"/>
    <text x="{{.X}}" y="{{.Y}}" dx="9" dy="-4" text-anchor="middle" font-size="10" fill="#7c1d16">{{.Drift}}</text>
{{if .Label}}    <text x="{{.X}}" y="{{$.PlotBottom}}" dx="9" dy="14" text-anchor="middle" font-size="10" fill="#555">{{.Label}}</text>
{{end}}  </g>
{{end}}</svg>`))
