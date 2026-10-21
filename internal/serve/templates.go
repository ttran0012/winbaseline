package serve

import (
	"embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/ttran0012/winbaseline/internal/report"
)

// The pages and the stylesheet are built into the binary, so the dashboard has
// nothing to load from the disk or the network at runtime.

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static/dashboard.css
var dashboardCSS []byte

// styleSheet is what /style.css serves: the report's own styling for statuses
// and results tables, plus the layout the dashboard adds around it. One setting
// then looks the same on screen as it does in a saved report.
var styleSheet = append(append([]byte(nil), report.SharedCSS...), dashboardCSS...)

// funcs are the few helpers the pages need. The class helpers come from the
// report package, so a status cannot be styled one way in a saved report and
// another way here.
var funcs = template.FuncMap{
	"statusClass":   report.StatusClass,
	"severityClass": report.SeverityClass,
	"changeClass":   report.ChangeClass,
	"upper":         strings.ToUpper,
}

// pages holds each page already parsed together with the layout, so a request
// never parses a template.
var pages = parsePages(
	"overview.html",
	"job.html",
	"scans.html",
	"scan.html",
	"compare.html",
	"baseline.html",
	"verify.html",
)

func parsePages(names ...string) map[string]*template.Template {
	out := make(map[string]*template.Template, len(names))
	for _, name := range names {
		out[name] = template.Must(template.New(name).Funcs(funcs).
			ParseFS(templateFiles, "templates/layout.html", "templates/"+name))
	}
	return out
}

// render writes one page. The page is built in memory first: a template that
// fails halfway through would otherwise leave a half-written page behind a 200.
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	t, ok := pages[name]
	if !ok {
		http.Error(w, "no such page", http.StatusNotFound)
		return
	}
	var body strings.Builder
	if err := t.ExecuteTemplate(&body, "layout", data); err != nil {
		http.Error(w, "could not render this page: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body.String()))
}
