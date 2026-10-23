package serve

import (
	"embed"
	"html/template"
	"net/http"
	"strings"
)

// The pages and the stylesheet are built into the binary, so the dashboard has
// nothing to load from the disk or the network at runtime.

//go:embed templates/*.html
var templateFiles embed.FS

//go:embed static/dashboard.css
var dashboardCSS []byte

// styleSheet is what /style.css serves. The saved HTML report keeps its own
// styles inline, because a file that gets emailed has to carry them; the
// dashboard has the design system in docs/ui-mockup.html instead.
var styleSheet = dashboardCSS

// funcs are the helpers the pages need: which badge class a value wears, and
// upper-casing for the short labels.
var funcs = template.FuncMap{
	"badgeStatus": badgeStatus,
	"badgeChange": badgeChange,
	"badgeState":  badgeState,
	"sevClass":    severityClass,
	"kpiTone":     kpiTone,
	"upper":       strings.ToUpper,
	"lower":       strings.ToLower,
}

// pages holds each page already parsed together with the layout, so a request
// never parses a template.
var pages = parsePages(
	"fleet.html",
	"computer.html",
	"results.html",
	"compare.html",
	"scanpage.html",
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
