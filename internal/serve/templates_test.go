package serve

import (
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
	"testing"
)

// The pages are served with a content security policy of style-src 'self',
// which blocks a style attribute and an inline <style> block outright. The
// mockup used both; every one of them is a class in dashboard.css now. A
// template that grows one again would look fine on the author's screen and
// silently lose its styling in the browser, so it is a test, not a note.
func TestTemplatesCarryNoInlineStyles(t *testing.T) {
	styleAttr := regexp.MustCompile(`(?i)\sstyle\s*=`)
	styleTag := regexp.MustCompile(`(?i)<style[\s>]`)

	files, err := fs.Glob(templateFiles, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no templates were found to check")
	}
	for _, name := range files {
		t.Run(path.Base(name), func(t *testing.T) {
			data, err := fs.ReadFile(templateFiles, name)
			if err != nil {
				t.Fatal(err)
			}
			if loc := styleAttr.FindIndex(data); loc != nil {
				t.Errorf("contains a style attribute, which the content security policy blocks: %q",
					excerpt(data, loc[0]))
			}
			if loc := styleTag.FindIndex(data); loc != nil {
				t.Errorf("contains an inline <style> block, which the content security policy blocks: %q",
					excerpt(data, loc[0]))
			}
		})
	}
}

// And the same for what the pages actually send, including the SVG the fleet
// and computer pages draw in Go.
func TestRenderedPagesCarryNoInlineStyles(t *testing.T) {
	s, saved := testServer(t)
	s.hostsPath = hostList(t, s.dir, "SQL-02", "2026-12-31")

	for _, target := range []string{
		"/", "/computer", "/scan", "/scan?file=" + saved[0].File,
		"/compare", "/baseline", "/verify",
	} {
		t.Run(target, func(t *testing.T) {
			body := get(t, s, target).Body.String()
			for _, forbidden := range []string{"style=", "<style"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("the page contains %q", forbidden)
				}
			}
		})
	}
}

// The stylesheet is the design system, served as a file.
func TestStylesheetIsTheDesignSystem(t *testing.T) {
	s, _ := testServer(t)
	body := get(t, s, "/style.css").Body.String()

	// The tokens and the components the mockup defines.
	for _, want := range []string{
		"--drift:", "--chg:", "--ok:", "--exc:", "--mute:", "--brand:",
		".card", ".kpi", ".badge", ".b-drift", ".b-error", ".b-exc", ".b-ok", ".b-chg", ".b-mute",
		".chips", ".chip", "details.group", ".tabs", ".alert", ".list", ".steps", ".bar",
		".facts", ".val", ".topbar", ".spark",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the stylesheet is missing %q", want)
		}
	}
	// The mock-only rules have no business here.
	for _, forbidden := range []string{".mockbar", ".screen", ":target"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the stylesheet still carries the mockup-only rule %q", forbidden)
		}
	}
	// And nothing is fetched from anywhere.
	for _, forbidden := range []string{"http://", "https://", "@import", "url("} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the stylesheet reaches outside the binary: %q", forbidden)
		}
	}
}

// The progress bars are three fixed widths, because a percentage would have to
// travel in a style attribute.
func TestProgressBarsUseClassesNotWidths(t *testing.T) {
	s, _ := testServer(t)
	release, ready := make(chan struct{}), make(chan struct{})
	if _, err := s.runner.start([]string{"SQL-02", "DC-01"}, testNow, func(rec *recorder) {
		rec.done(jobResult{Host: "SQL-02", Code: 0})
		rec.reading("DC-01")
		close(ready) // one finished, one in progress, one not started
		<-release
		rec.done(jobResult{Host: "DC-01", Code: 1})
	}); err != nil {
		t.Fatal(err)
	}
	defer close(release)
	<-ready

	body := get(t, s, "/scan").Body.String()
	for _, want := range []string{`<i class="full">`, `<i class="half">`} {
		if !strings.Contains(body, want) {
			t.Errorf("the progress list is missing %q", want)
		}
	}
	if strings.Contains(body, "width:") {
		t.Error("a bar width reached the page as CSS")
	}
}

func excerpt(data []byte, at int) string {
	start := at - 40
	if start < 0 {
		start = 0
	}
	end := at + 40
	if end > len(data) {
		end = len(data)
	}
	return string(data[start:end])
}

// Every page the nav offers has to answer, and the nav has to mark where it is.
func TestNavigation(t *testing.T) {
	s, _ := testServer(t)
	tests := map[string]string{
		"/":         "Fleet",
		"/scan":     "Scan",
		"/baseline": "Baseline",
		"/verify":   "Evidence",
	}
	for target, label := range tests {
		t.Run(target, func(t *testing.T) {
			rec := get(t, s, target)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", target, rec.Code)
			}
			body := rec.Body.String()
			// All four links are on every page.
			for _, want := range []string{">Fleet<", ">Scan<", ">Baseline<", ">Evidence<"} {
				if !strings.Contains(body, want) {
					t.Errorf("the nav is missing %s", want)
				}
			}
			// And this page is the one marked current.
			marked := `class="here" aria-current="page">` + label + `<`
			if !strings.Contains(body, marked) {
				t.Errorf("%s should be marked as the current page", label)
			}
		})
	}
}

// The top bar says what the evidence is doing on every page, so a broken chain
// cannot be missed by being on the wrong page.
func TestEveryPageShowsTheEvidenceState(t *testing.T) {
	s, _ := testServer(t)
	for _, target := range []string{"/", "/computer", "/scan", "/baseline", "/verify"} {
		if body := get(t, s, target).Body.String(); !strings.Contains(body, "Evidence verified") {
			t.Errorf("%s does not show the evidence state", target)
		}
	}
}
