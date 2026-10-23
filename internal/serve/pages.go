package serve

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

// chrome is what every page carries: the title, which nav link is current, the
// computer being looked at so the tabs keep it, the form token, and the state
// of the evidence, which the top bar shows on every page.
type chrome struct {
	Title string
	Nav   string
	Dir   string
	Host  string
	CSRF  string
	Addr  string
	Chain chainStatus
}

func (s *Server) page(title, nav, host string) chrome {
	return chrome{
		Title: title, Nav: nav, Dir: s.dir, Host: host,
		CSRF: s.csrf, Addr: s.addr, Chain: s.verifyChains(),
	}
}

// ---------- fleet ----------

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "no such page", http.StatusNotFound)
		return
	}
	head := s.page("Fleet", "fleet", "")
	computers := s.fleet()
	b, _ := s.loadBaseline()

	data := struct {
		chrome
		Computers     []computer
		Attention     []attention
		NeedAttention int
		Changed       int
		ChangedWhere  string
		Drift         int
		DriftHigh     int
		Approved      int
		LastScan      string
		Running       bool
	}{chrome: head, Computers: computers}

	var changedOn []string
	for _, c := range computers {
		if !c.Settled() {
			data.NeedAttention++
		}
		if c.Approved {
			data.Approved++
		}
		if c.Latest == nil {
			continue
		}
		data.Drift += c.Latest.Scan.Summary.Drift
		data.DriftHigh += highSeverity(c.Latest.Scan.Results)
		if n := c.Latest.Scan.Summary.Changed; n > 0 {
			data.Changed += n
			changedOn = append(changedOn, c.Host)
		}
		if data.LastScan == "" {
			data.LastScan = c.Since
		}
	}
	if len(changedOn) > 0 {
		data.ChangedWhere = "on " + strings.Join(changedOn, ", ")
	}
	data.Attention = s.attentionList(computers, b, head.Chain)
	_, data.Running = s.runner.state()
	s.render(w, "fleet.html", data)
}

// ---------- one computer ----------

func (s *Server) computerPage(w http.ResponseWriter, r *http.Request) {
	src, ix, ok := s.openSource(w, r)
	if !ok {
		return
	}
	all := ix.loadAll()
	newest, previous := latest(all)

	var me computer
	for _, c := range s.fleet() {
		if c.Key == src.Key {
			me = c
			break
		}
	}

	data := struct {
		chrome
		Computer   computer
		Scans      []*savedScan
		Newest     *savedScan
		Previous   *savedScan
		Changed    []changedRow
		NewDrift   []compare.Result
		Trend      template.HTML
		DriftMove  string
		Captures   int
		ScannedAs  string
		SoonestExc string
	}{
		chrome:    s.page(me.Host, "fleet", src.Key),
		Computer:  me,
		Newest:    newest,
		Previous:  previous,
		Trend:     trendChart(all),
		ScannedAs: collect.CurrentUser(),
	}
	for i := len(all) - 1; i >= 0; i-- {
		data.Scans = append(data.Scans, all[i])
	}
	if entries, err := report.ReadChain(captureFolder(src.Dir)); err == nil {
		data.Captures = len(entries)
	}
	if newest != nil {
		if newest.Scan.Capture != nil {
			data.Changed = changedRows(newest.Scan)
		} else if previous != nil {
			data.NewDrift = newDrift(previous.Scan, newest.Scan)
		}
		if previous != nil {
			move := newest.Scan.Summary.Drift - previous.Scan.Summary.Drift
			if move == 0 {
				data.DriftMove = "unchanged since the previous scan"
			} else {
				data.DriftMove = fmt.Sprintf("%+d since the previous scan", move)
			}
		}
	}
	if b, _ := s.loadBaseline(); b != nil {
		now := s.now()
		soonest := 0
		for _, e := range b.Exceptions {
			if exp := exceptionExpiry(e, now); exp.Label == "soon" && (soonest == 0 || exp.Days < soonest) {
				soonest = exp.Days
			}
		}
		if soonest > 0 {
			data.SoonestExc = fmt.Sprintf("1 exception expires in %d days", soonest)
		}
	}
	s.render(w, "computer.html", data)
}

// ---------- one scan's results ----------

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

	s.render(w, "results.html", struct {
		chrome
		Saved       *savedScan
		Groups      []resultGroup
		Shown       int
		Chips       chipSet
		Filter      filter
		HTMLReport  string
		BaselineErr string
		Scans       int
	}{
		chrome:      s.page("Scan results", "fleet", src.Key),
		Saved:       saved,
		Groups:      groupResults(shown, types),
		Shown:       len(shown),
		Chips:       chips(src.Key, saved.Entry.File, f, saved.Scan.Results),
		Filter:      f,
		HTMLReport:  htmlReportName(src.Dir, saved.Entry.File),
		BaselineErr: baselineErr,
		Scans:       len(ix.entries),
	})
}

// htmlReportName is the saved HTML view beside a scan, when one was written.
func htmlReportName(dir, file string) string {
	name := strings.TrimSuffix(file, ".json") + ".html"
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
		return ""
	}
	return name
}

// ---------- compare ----------

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
		Newest     *savedScan
	}{
		chrome: s.page("Compare scans", "fleet", src.Key),
		Scans:  all,
		Newest: newest,
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

// ---------- scan: start, progress, manage ----------

func (s *Server) scanPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("file") != "" {
		s.scanDetail(w, r)
		return
	}
	j, running := s.runner.state()
	hosts, hostsErr := s.hosts()
	managed, _, manageErr := s.managedHosts()

	data := struct {
		chrome
		Job        *job
		Running    bool
		Steps      []step
		Approved   []fleet.Host
		HostsErr   string
		ManageErr  string
		Managed    []managedHost
		Skipped    int
		Authorized bool
		Scope      string
		ApprovedBy string
		Expires    string
		ScannedAs  string
		Elevated   bool
		HostsFile  string
		HasList    bool
		Timeout    string
	}{
		chrome:    s.page("Scan", "scan", ""),
		Job:       j,
		Running:   running,
		Steps:     steps(j, running),
		Managed:   managed,
		ManageErr: manageErr,
		ScannedAs: collect.CurrentUser(),
		Elevated:  collect.IsElevated(),
		HostsFile: s.hostsPath,
		HasList:   s.hostsPath != "",
		Timeout:   collect.AccessTimeout.String(),
	}
	for _, m := range managed {
		if m.Skip {
			data.Skipped++
		}
	}
	if hostsErr != nil {
		data.HostsErr = hostsErr.Error()
	} else {
		a := hosts.Authorization
		data.Scope, data.ApprovedBy, data.Expires = a.Scope, a.ApprovedBy, a.Expires
		if err := hosts.Authorized(s.now()); err != nil {
			data.HostsErr = err.Error()
		} else {
			data.Authorized = true
			data.Approved, _ = hosts.Targets("")
		}
	}
	s.render(w, "scanpage.html", data)
}

// step is one computer's line in the progress list.
type step struct {
	Host  string
	Fill  string // full, half or none: the scanner knows done, reading, or waiting
	Done  bool
	Badge string
	Label string
	Note  string
}

// steps lines the computers a job was asked for up against what it has
// reported, so the list shows what is finished, what is being read now, and
// what is still waiting.
func steps(j *job, running bool) []step {
	if j == nil {
		return nil
	}
	done := map[string]jobResult{}
	for _, res := range j.Results {
		done[res.Host] = res
	}
	out := make([]step, 0, len(j.Targets))
	for _, host := range j.Targets {
		st := step{Host: host, Fill: "none", Note: "waiting"}
		if res, ok := done[host]; ok {
			st.Fill, st.Done, st.Note = "full", true, ""
			switch {
			case res.Err != "":
				st.Badge, st.Label = "b-drift", "NOT SAVED"
			case res.Code == 2:
				st.Badge, st.Label = "b-drift", "NOTHING READ"
			case res.Code == 3:
				st.Badge, st.Label = "b-error", "EVIDENCE SUSPECT"
			case res.Summary.Drift > 0:
				st.Badge, st.Label = "b-drift", fmt.Sprintf("%d DRIFT", res.Summary.Drift)
			case res.Summary.Errors > 0:
				st.Badge, st.Label = "b-error", "PARTIAL"
			case res.Summary.Changed > 0:
				st.Badge, st.Label = "b-chg", fmt.Sprintf("%d CHANGED", res.Summary.Changed)
			default:
				st.Badge, st.Label = "b-ok", "CLEAN"
			}
		} else if running && host == j.Current {
			st.Fill, st.Note = "half", "reading settings"
		}
		out = append(out, st)
	}
	return out
}

// startScan is the request that starts a scan. It checks that the form came
// from this dashboard, that the computer is one the host list approves, and
// that no scan is already running, then starts one and sends the browser back
// to the progress page.
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
	http.Redirect(w, r, "/scan", http.StatusSeeOther)
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

// ---------- baseline and evidence ----------

// exceptionRow is one approved exception as the baseline page lists it.
type exceptionRow struct {
	baseline.Exception
	Expiry expiry
}

func (s *Server) baselinePage(w http.ResponseWriter, r *http.Request) {
	b, loadErr := s.loadBaseline()
	data := struct {
		chrome
		Baseline   *baseline.Baseline
		Types      []typeRow
		Exceptions []exceptionRow
		Expiring   []exceptionRow
		InForce    int
		Err        string
		Soon       int
		Path       string
	}{
		chrome: s.page("Baseline", "baseline", ""),
		Err:    loadErr,
		Soon:   int(expiringSoon.Hours() / 24),
		Path:   s.baselinePath,
	}
	if b != nil {
		data.Baseline = b
		data.Types = checksByType(b)
		now := s.now()
		for _, e := range b.Exceptions {
			row := exceptionRow{Exception: e, Expiry: exceptionExpiry(e, now)}
			data.Exceptions = append(data.Exceptions, row)
			if row.Expiry.Label == "expired" {
				continue
			}
			data.InForce++
			if row.Expiry.Label == "soon" {
				data.Expiring = append(data.Expiring, row)
			}
		}
		for _, row := range data.Exceptions {
			if row.Expiry.Label == "expired" {
				data.Expiring = append(data.Expiring, row)
			}
		}
	}
	s.render(w, "baseline.html", data)
}

func (s *Server) verifyPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "verify.html", struct {
		chrome
		CheckedAt time.Time
	}{chrome: s.page("Evidence", "verify", ""), CheckedAt: s.now()})
}

// ---------- plumbing ----------

// movedToComputer and movedToScan keep the addresses these pages used to have.
func (s *Server) movedToComputer(w http.ResponseWriter, r *http.Request) {
	to := "/computer"
	if host := r.URL.Query().Get("host"); host != "" {
		to += "?host=" + url.QueryEscape(host)
	}
	http.Redirect(w, r, to, http.StatusFound)
}

func (s *Server) movedToScan(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/scan", http.StatusFound)
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
