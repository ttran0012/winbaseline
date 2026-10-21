// Package serve runs a local dashboard over the evidence the scanner saves,
// and can start a scan.
//
// Scan results describe how a computer is defended, and starting a scan reaches
// other computers, so the dashboard is deliberately the narrowest thing that
// does the job:
//
//   - It listens on the loopback interface only, and refuses to start anywhere
//     else.
//   - Every page is a GET. The single exception is the form that starts a scan,
//     which is a POST carrying a token from a page this server rendered.
//   - A scan it starts reads settings and writes evidence. It changes nothing on
//     any computer, installs nothing, and holds no credentials: a remote read
//     happens as the account the dashboard runs as.
//   - It can only name a computer the approved host list names, and only while
//     that approval is in date.
//   - It reads a saved file only when that folder's ledger lists it, so no
//     request can reach a file the scanner did not write.
//   - It needs nothing from the network: no scripts, no fonts, no CDN. It works
//     the same on a disconnected machine.
package serve

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ttran0012/winbaseline/internal/fleet"
)

// startScanPath is the one path that accepts a POST.
const startScanPath = "/scan/start"

// Server answers the dashboard pages for one results folder.
type Server struct {
	dir          string // the results folder, holding the scans and their ledgers
	baselinePath string
	hostsPath    string
	writeHTML    bool
	now          func() time.Time
	csrf         string // a token for this process, embedded in the scan form
	runner       runner
	mux          *http.ServeMux
}

// Options configure a Server. Now is settable so that what counts as an expired
// approval, or a computer that has stopped reporting, can be tested.
type Options struct {
	Dir          string
	BaselinePath string
	HostsPath    string // the approved host list; without it, only this computer can be scanned
	WriteHTML    bool
	Now          func() time.Time
}

// New builds the dashboard. It reads nothing until a request arrives, so every
// page shows the evidence as it is on disk at that moment.
func New(o Options) *Server {
	s := &Server{
		dir:          o.Dir,
		baselinePath: o.BaselinePath,
		hostsPath:    o.HostsPath,
		writeHTML:    o.WriteHTML,
		now:          o.Now,
		csrf:         newToken(),
		mux:          http.NewServeMux(),
	}
	if s.now == nil {
		s.now = time.Now
	}

	s.mux.HandleFunc("/", s.overview)
	s.mux.HandleFunc("/scans", s.scans)
	s.mux.HandleFunc("/scan", s.scanDetail)
	s.mux.HandleFunc(startScanPath, s.startScan)
	s.mux.HandleFunc("/job", s.jobPage)
	s.mux.HandleFunc("/compare", s.compare)
	s.mux.HandleFunc("/baseline", s.baselinePage)
	s.mux.HandleFunc("/verify", s.verifyPage)
	s.mux.HandleFunc("/style.css", s.stylesheet)
	return s
}

// ServeHTTP applies the rules that hold for every request before routing: the
// security headers go on every response, including the refusals, and the only
// method that reaches a handler is GET, plus a POST to the one path that starts
// a scan.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())
	switch {
	case r.Method == http.MethodGet:
	case r.Method == http.MethodPost && r.URL.Path == startScanPath:
	default:
		w.Header().Set("Allow", "GET")
		http.Error(w, "the dashboard answers GET, and a POST only to "+startScanPath,
			http.StatusMethodNotAllowed)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// setSecurityHeaders tells the browser to fetch nothing: no scripts at all, no
// images or stylesheets from anywhere but this server, and no form posted
// anywhere else. The pages are built to need nothing more, so the policy can be
// this narrow.
func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
}

// checkTrustedForm rejects anything that did not come from a form this server
// rendered. The token cannot be read by another site, because the browser will
// not let one read this page, and the origin check turns away a request that
// came from somewhere else even if the token leaked.
func (s *Server) checkTrustedForm(r *http.Request) error {
	// Sec-Fetch-Site is the dependable signal, and the browser will not let
	// another site forge it. "none" is a request the person started themselves,
	// by typing or from a bookmark.
	switch site := r.Header.Get("Sec-Fetch-Site"); site {
	case "", "same-origin", "none":
	default:
		return fmt.Errorf("this request was sent from another site (%s)", site)
	}
	// Origin is only checked when it names somewhere. These pages are served
	// with Referrer-Policy: no-referrer, and the Fetch standard says a form
	// posted from such a page carries Origin: null rather than this server's
	// name, so a literal "null" says nothing either way and is not a reason to
	// refuse. The token below is what actually proves where the form came from.
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		if err != nil || u.Host != r.Host {
			return fmt.Errorf("this request came from %s, which is not this dashboard", origin)
		}
	}
	// The token cannot be read by another site, because the browser will not
	// let one read this page.
	got := r.PostFormValue("csrf")
	if subtle.ConstantTimeCompare([]byte(got), []byte(s.csrf)) != 1 {
		return fmt.Errorf("this form did not come from this dashboard, or the dashboard has restarted since the page was loaded")
	}
	return nil
}

// hosts reads the approved host list.
func (s *Server) hosts() (*fleet.Hosts, error) {
	if s.hostsPath == "" {
		return nil, fmt.Errorf("no host list was given to -hosts, so only this computer can be scanned")
	}
	return fleet.Load(s.hostsPath)
}

// newToken is a per-process form token. It is not a session: the dashboard has
// one user, the person at the keyboard.
func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail in practice; if it ever did, a dashboard
		// that cannot start a scan is better than one with a guessable token.
		return ""
	}
	return hex.EncodeToString(b)
}

// ListenAndServe starts the dashboard on addr, which has to be a loopback
// address.
func (s *Server) ListenAndServe(addr string) error {
	if err := CheckLoopback(addr); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// CheckLoopback refuses any address that is not on the loopback interface.
// Saved scans name the gaps in a computer's defenses, and this dashboard can
// start a scan, so it is for the person sitting at the machine and is never
// published to a network: that has to be a property of the tool, not a thing
// the operator remembers.
func CheckLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address %q must be host:port, such as 127.0.0.1:8080", addr)
	}
	if port == "" {
		return fmt.Errorf("address %q needs a port, such as 127.0.0.1:8080", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		where := fmt.Sprintf("%q", host)
		if host == "" {
			where = "every network interface"
		}
		return fmt.Errorf("refusing to serve on %s: the dashboard must be addressed by a loopback IP, "+
			"such as 127.0.0.1:8080 or [::1]:8080, because saved scans are not for the network to read", where)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("refusing to serve on %s: that is not a loopback address, and saved scans "+
			"are not for the network to read; use 127.0.0.1 or [::1]", host)
	}
	return nil
}
