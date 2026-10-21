package serve

import (
	"errors"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/fleet"
	"github.com/ttran0012/winbaseline/internal/report"
	"github.com/ttran0012/winbaseline/internal/scan"
)

// scanAll is the value the form uses for every approved computer at once.
const scanAll = "*"

// chrome is what every page carries: the title, which nav link is the current
// one, and the computer being looked at, so the nav keeps it.
type chrome struct {
	Title string
	Nav   string
	Dir   string
	Host  string // the ?host= key, empty for this computer
	CSRF  string
}

func (s *Server) page(title, nav, host string) chrome {
	return chrome{Title: title, Nav: nav, Dir: s.dir, Host: host, CSRF: s.csrf}
}

// overview is the front page: every computer, worst first.
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "no such page", http.StatusNotFound)
		return
	}
	j, running := s.runner.state()
	hosts, hostsErr := s.hosts()

	data := struct {
		chrome
		Computers  []computer
		Chain      chainStatus
		Job        *job
		Running    bool
		CanScan    bool
		Approved   []fleet.Host
		HostsErr   string
		ScannedAs  string
		Authorized string
	}{
		chrome:    s.page("Overview", "overview", ""),
		Computers: s.fleet(),
		Chain:     s.verifyChains(),
		Job:       j,
		Running:   running,
		ScannedAs: collect.CurrentUser(),
	}
	if hostsErr != nil {
		data.HostsErr = hostsErr.Error()
	} else {
		a := hosts.Authorization
		data.Authorized = "Approved by " + a.ApprovedBy + " on " + a.Approved +
			", until " + a.Expires + ": " + a.Scope
		if err := hosts.Authorized(s.now()); err != nil {
			data.HostsErr = err.Error()
		} else {
			data.Approved, _ = hosts.Targets("")
		}
	}
	// This computer can always be scanned; others only while an approval is in date.
	data.CanScan = !running
	s.render(w, "overview.html", data)
}

// startScan is the only request that is not a read. It checks that the form
// came from this dashboard, that the computer is one the host list approves,
// and that no scan is already running, then starts one and sends the browser to
// the job page.
func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	if err := s.checkTrustedForm(r); err != nil {
		http.Error(w, "refusing to start a scan: "+err.Error(), http.StatusForbidden)
		return
	}
	targets, err := s.chooseTargets(r.PostFormValue("target"))
	if err != nil {
		http.Error(w, "refusing to start a scan: "+err.Error(), http.StatusForbidden)
		return
	}
	b, err := baseline.Load(s.baselinePath)
	if err != nil {
		http.Error(w, "cannot scan: the baseline would not load: "+err.Error(), http.StatusInternalServerError)
		return
	}

	names := make([]string, 0, len(targets))
	for _, t := range targets {
		names = append(names, displayHost(t))
	}
	at := s.now()
	opts := scan.Options{
		Baseline:  b,
		LocalHost: localHost(),
		At:        at,
		Elevated:  collect.IsElevated(),
	}
	if _, err := s.runner.start(names, at, func(rec *recorder) {
		for _, t := range targets {
			host := displayHost(t)
			rec.reading(host)
			result := scan.Read(t, opts)
			saved, err := scan.Save(t, result, s.writeHTML)
			rec.done(resultOf(host, result, saved, err))
		}
	}); err != nil {
		if errors.Is(err, errScanRunning) {
			http.Error(w, "a scan is already running; wait for it to finish", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/job", http.StatusSeeOther)
}

// chooseTargets turns what the form asked for into the computers that may be
// read. This computer is always allowed. Any other has to be named in the host
// list, with an approval that is still in date, because a dashboard that can
// scan whatever it is told to is a different and much worse tool.
func (s *Server) chooseTargets(choice string) ([]scan.Target, error) {
	if choice == "" {
		return []scan.Target{{Dir: s.dir}}, nil
	}
	hosts, err := s.hosts()
	if err != nil {
		return nil, err
	}
	if err := hosts.Authorized(s.now()); err != nil {
		return nil, err
	}
	picked, err := hosts.Targets(pickHost(choice))
	if err != nil {
		return nil, err
	}
	targets := make([]scan.Target, 0, len(picked))
	for _, h := range picked {
		targets = append(targets, scan.Target{
			Host:  h.Name,
			Label: h.Label,
			Dir:   filepath.Join(s.dir, h.Name),
		})
	}
	return targets, nil
}

// pickHost maps the form value to what the host list expects: all of them, or
// one by name.
func pickHost(choice string) string {
	if choice == scanAll {
		return ""
	}
	return choice
}

func displayHost(t scan.Target) string {
	if t.Host == "" {
		return localHost()
	}
	return t.Host
}

// localHost is the name of the computer the dashboard runs on.
func localHost() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "this computer"
	}
	return host
}

// jobPage shows the scan that is running, or the last one that finished. While
// a scan is running the page refreshes itself, which needs no script.
func (s *Server) jobPage(w http.ResponseWriter, r *http.Request) {
	j, running := s.runner.state()
	s.render(w, "job.html", struct {
		chrome
		Job     *job
		Running bool
	}{
		chrome:  s.page("Scan progress", "overview", ""),
		Job:     j,
		Running: running,
	})
}

// scans lists every scan recorded for one computer.
func (s *Server) scans(w http.ResponseWriter, r *http.Request) {
	src, ix, ok := s.openSource(w, r)
	if !ok {
		return
	}
	all := ix.loadAll()
	newest, previous := latest(all)
	// Newest first: that is the one being asked about.
	reversed := make([]*savedScan, 0, len(all))
	for i := len(all) - 1; i >= 0; i-- {
		reversed = append(reversed, all[i])
	}

	data := struct {
		chrome
		Scans    []*savedScan
		Local    bool
		Newest   *savedScan
		Previous *savedScan
		Changed  []compare.Result
		NewDrift []compare.Result
		Trend    template.HTML
	}{
		chrome: s.page("Scans", "scans", src.Key),
		Scans:  reversed,
		Local:  src.Local,
		Newest: newest, Previous: previous,
		Trend: trendChart(all),
	}
	if newest != nil {
		// With a capture, the interesting list is what moved away from the
		// configuration this computer was approved with. Without one, the best
		// the evidence can offer is what the previous scan did not find.
		if newest.Scan.Capture != nil {
			data.Changed = changedSinceCapture(newest.Scan)
		} else if previous != nil {
			data.NewDrift = newDrift(previous.Scan, newest.Scan)
		}
	}
	s.render(w, "scans.html", data)
}

// scanDetail shows one scan's results, narrowed by the query string.
func (s *Server) scanDetail(w http.ResponseWriter, r *http.Request) {
	src, ix, ok := s.openSource(w, r)
	if !ok {
		return
	}
	saved, err := ix.load(r.URL.Query().Get("file"))
	if errors.Is(err, errUnknownScan) {
		http.Error(w, "no such scan in this results folder", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b, baselineErr := s.loadBaseline()
	types := checkTypes(b)
	f := readFilter(r.URL.Query())

	var shown []compare.Result
	for _, res := range report.SortForReport(saved.Scan.Results) {
		if f.match(res, types) {
			shown = append(shown, res)
		}
	}
	s.render(w, "scan.html", struct {
		chrome
		Saved       *savedScan
		Results     []compare.Result
		Filter      filter
		Statuses    []string
		Severities  []string
		Types       []string
		TypesKnown  bool
		BaselineErr string
	}{
		chrome:      s.page("Scan", "scans", src.Key),
		Saved:       saved,
		Results:     shown,
		Filter:      f,
		Statuses:    knownStatus,
		Severities:  knownSeverity,
		Types:       knownTypes,
		TypesKnown:  baselineErr == "",
		BaselineErr: baselineErr,
	})
}

// compare puts two of one computer's scans side by side.
func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	src, ix, ok := s.openSource(w, r)
	if !ok {
		return
	}
	all := ix.loadAll()
	newest, previous := latest(all)

	q := r.URL.Query()
	fromName, toName := q.Get("a"), q.Get("b")
	if fromName == "" && previous != nil {
		fromName = previous.Entry.File
	}
	if toName == "" && newest != nil {
		toName = newest.Entry.File
	}

	data := struct {
		chrome
		Scans      []*savedScan
		From, To   *savedScan
		Comparison comparison
		Problem    string
	}{
		chrome: s.page("Compare", "compare", src.Key),
		Scans:  all,
	}
	if fromName != "" && toName != "" {
		from, errA := ix.load(fromName)
		to, errB := ix.load(toName)
		switch {
		case errors.Is(errA, errUnknownScan) || errors.Is(errB, errUnknownScan):
			http.Error(w, "no such scan in this results folder", http.StatusNotFound)
			return
		case errA != nil:
			data.Problem = errA.Error()
		case errB != nil:
			data.Problem = errB.Error()
		case from.Err != "":
			data.Problem = from.Entry.File + " " + from.Err
		case to.Err != "":
			data.Problem = to.Entry.File + " " + to.Err
		default:
			data.From, data.To = from, to
			data.Comparison = compareScans(from.Scan, to.Scan)
		}
	}
	s.render(w, "compare.html", data)
}

// exceptionRow is one approved exception as the baseline page lists it.
type exceptionRow struct {
	baseline.Exception
	Expiry expiry
}

// baselinePage shows the policy itself: what is checked, and what has been
// approved as an exception to it.
func (s *Server) baselinePage(w http.ResponseWriter, r *http.Request) {
	b, loadErr := s.loadBaseline()
	data := struct {
		chrome
		Baseline   *baseline.Baseline
		Exceptions []exceptionRow
		Err        string
		Soon       int
	}{
		chrome: s.page("Baseline", "baseline", ""),
		Err:    loadErr,
		Soon:   int(expiringSoon.Hours() / 24),
	}
	if b != nil {
		data.Baseline = b
		now := s.now()
		for _, e := range b.Exceptions {
			data.Exceptions = append(data.Exceptions, exceptionRow{Exception: e, Expiry: exceptionExpiry(e, now)})
		}
	}
	s.render(w, "baseline.html", data)
}

// verifyPage re-runs the chain checks on request.
func (s *Server) verifyPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "verify.html", struct {
		chrome
		Chain     chainStatus
		CheckedAt time.Time
	}{
		chrome:    s.page("Verify evidence", "verify", ""),
		Chain:     s.verifyChains(),
		CheckedAt: s.now(),
	})
}

// openSource resolves the ?host= a page was asked for and reads its ledger. The
// key has to match a folder the dashboard found by listing the results folder.
func (s *Server) openSource(w http.ResponseWriter, r *http.Request) (source, *index, bool) {
	src, err := s.source(r.URL.Query().Get("host"))
	if err != nil {
		http.Error(w, "no evidence folder for that computer", http.StatusNotFound)
		return source{}, nil, false
	}
	ix, err := readIndex(src.Dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return source{}, nil, false
	}
	return src, ix, true
}

// loadBaseline reads the baseline, returning the reason as text when it cannot:
// a missing or broken baseline file should not take the whole dashboard down,
// since every other page is about evidence already saved.
func (s *Server) loadBaseline() (*baseline.Baseline, string) {
	if s.baselinePath == "" {
		return nil, "no baseline file was given to -baseline"
	}
	b, err := baseline.Load(s.baselinePath)
	if err != nil {
		return nil, err.Error()
	}
	return b, ""
}

// stylesheet serves the one stylesheet the pages load. It is a file rather than
// an inline style block so that the content security policy can forbid inline
// CSS outright.
func (s *Server) stylesheet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(styleSheet)
}
