package serve

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/fleet"
)

// Managing the host list is the only thing the dashboard writes outside the
// results folder, and what it writes is the authorized scope itself. So every
// change goes through the same gate as starting a scan - a POST from a form
// this server rendered - and then through fleet's own rules, which refuse any
// change while the approval is missing, unfinished, or out of date. Adding a
// computer also asks the person to confirm, in as many words, that it is inside
// the scope somebody signed for.

// manage paths.
const (
	addHostPath    = "/hosts/add"
	skipHostPath   = "/hosts/skip"
	removeHostPath = "/hosts/remove"
	testHostPath   = "/hosts/test"
)

// probes remembers the last read-only access probe for each computer, so the
// answer survives the redirect back to the page that asked for it.
type probes struct {
	mu   sync.Mutex
	last map[string]collect.AccessReport
}

func (p *probes) set(host string, report collect.AccessReport) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == nil {
		p.last = map[string]collect.AccessReport{}
	}
	p.last[strings.ToLower(host)] = report
}

func (p *probes) get(host string) (collect.AccessReport, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.last[strings.ToLower(host)]
	return r, ok
}

// managedHost is one row of the Manage computers table.
type managedHost struct {
	fleet.Host
	Access collect.AccessReport
	Probed bool
}

// Added reads as "Oct 15 · itadmin" when the entry records it.
func (m managedHost) AddedLine() string {
	switch {
	case m.Added == "" && m.AddedBy == "":
		return "not recorded"
	case m.AddedBy == "":
		return m.Added
	case m.Added == "":
		return m.AddedBy
	}
	return m.Added + " · " + m.AddedBy
}

// AccessLabel is the badge for the remote access column.
func (m managedHost) AccessLabel() string {
	switch {
	case m.Skip:
		return "SKIPPED"
	case !m.Probed:
		return "NOT TESTED"
	case m.Access.TimedOut:
		return "NO ANSWER"
	case m.Access.OK():
		return "REACHABLE"
	case m.Access.Registry != "":
		return "REMOTE REGISTRY OFF"
	}
	return "NO SERVICE ACCESS"
}

func (m managedHost) AccessBadge() string {
	switch {
	case m.Skip:
		return "b-mute"
	case !m.Probed:
		return "b-mute"
	case m.Access.OK():
		return "b-ok"
	}
	return "b-error"
}

// AccessHint says what to do about it, where there is something to do.
func (m managedHost) AccessHint() string {
	if m.Skip || !m.Probed || m.Access.OK() {
		return ""
	}
	if m.Access.Registry != "" && !m.Access.TimedOut {
		return "Start the Remote Registry service on " + m.Name + ", and give this account read access."
	}
	return m.Access.Summary()
}

// managedHosts is the host list as the Manage computers card shows it.
func (s *Server) managedHosts() ([]managedHost, *fleet.Hosts, string) {
	h, err := s.hosts()
	if err != nil {
		return nil, nil, err.Error()
	}
	out := make([]managedHost, 0, len(h.Hosts))
	for _, host := range h.Hosts {
		row := managedHost{Host: host}
		if report, ok := s.probes.get(host.Name); ok {
			row.Access, row.Probed = report, true
		}
		out = append(out, row)
	}
	return out, h, ""
}

// changeHosts is the one handler behind every button on the Manage computers
// card. It checks the form came from this dashboard, works out what was asked,
// and lets the fleet package decide whether the approval allows it.
func (s *Server) changeHosts(w http.ResponseWriter, r *http.Request) {
	if err := s.checkTrustedForm(r); err != nil {
		http.Error(w, "refusing to change the host list: "+err.Error(), http.StatusForbidden)
		return
	}
	if s.hostsPath == "" {
		http.Error(w, "refusing to change the host list: no host list was given to -hosts",
			http.StatusForbidden)
		return
	}
	by := collect.CurrentUser()
	now := s.now()
	name := strings.TrimSpace(r.PostFormValue("name"))

	var err error
	switch r.URL.Path {
	case addHostPath:
		// The approval is quoted on the form; adding a computer means saying it
		// falls inside it. Without that, there is nothing to record.
		if r.PostFormValue("confirm") == "" {
			err = fmt.Errorf("confirm that the computer is inside the approved scope before adding it")
			break
		}
		err = fleet.Add(s.hostsPath, fleet.Host{
			Name:  name,
			Label: strings.TrimSpace(r.PostFormValue("label")),
		}, by, now)
	case skipHostPath:
		err = fleet.SetSkip(s.hostsPath, name, r.PostFormValue("include") == "", by, now)
	case removeHostPath:
		err = fleet.Remove(s.hostsPath, name, by, now)
	case testHostPath:
		err = s.testAccess(name)
	default:
		http.Error(w, "no such page", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "refusing to change the host list: "+err.Error(), http.StatusForbidden)
		return
	}
	http.Redirect(w, r, "/scan#manage", http.StatusSeeOther)
}

// testAccess probes one computer, read-only. It is only offered for a computer
// on the list, or one being considered for it, and it reads no setting: it
// opens the two doors a scan would use and closes them again.
func (s *Server) testAccess(name string) error {
	if err := fleet.CheckName(name); err != nil {
		return err
	}
	h, err := s.hosts()
	if err != nil {
		return err
	}
	if err := h.Authorized(s.now()); err != nil {
		return err
	}
	s.probes.set(name, collect.TestAccess(name, collect.AccessTimeout))
	return nil
}
