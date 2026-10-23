package serve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/capture"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/fleet"
	"github.com/ttran0012/winbaseline/internal/report"
)

// The dashboard reads only what a ledger vouches for. A request names a scan by
// file name, and that name has to appear in that folder's chain.log exactly as
// given, so a request cannot reach a file the scanner did not write. Ledger
// lines are checked as well: a name that is not a plain file name is refused
// even if chain.log holds it, so editing a ledger cannot be turned into reading
// another folder. The same goes for the folders themselves: a computer is only
// reachable by a folder name the dashboard found by listing the results folder.

// errUnknownScan is returned for any file the ledger does not list.
var errUnknownScan = errors.New("no such scan in this results folder")

// errUnknownHost is returned for a computer with no evidence folder.
var errUnknownHost = errors.New("no evidence folder for that computer")

// staleAfter is how long a computer can go unscanned before the overview calls
// it out. A computer that quietly stopped reporting looks exactly like a
// compliant one if nobody is counting the days.
const staleAfter = 7 * 24 * time.Hour

// captureFolder is where captures live under a results folder.
func captureFolder(dir string) string { return filepath.Join(dir, capture.Dir) }

// source is one computer's folder of evidence. The results folder itself holds
// the scans of whichever computer the scanner ran on; a folder inside it holds
// the scans of the computer it is named after.
type source struct {
	Key   string // what a page passes in ?host=; empty for the results folder
	Dir   string
	Local bool
}

// sources lists the evidence folders under the results folder, this computer
// first. Only folders that actually hold a ledger are listed.
func (s *Server) sources() []source {
	out := []source{{Key: "", Dir: s.dir, Local: true}}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == capture.Dir {
			continue
		}
		dir := filepath.Join(s.dir, e.Name())
		if _, err := os.Stat(filepath.Join(dir, report.ChainLog)); err != nil {
			continue
		}
		out = append(out, source{Key: e.Name(), Dir: dir})
	}
	return out
}

// source resolves the ?host= value a page was given. The key has to match a
// folder the dashboard found, so no request can name a path of its own.
func (s *Server) source(key string) (source, error) {
	for _, src := range s.sources() {
		if src.Key == key {
			return src, nil
		}
	}
	return source{}, errUnknownHost
}

// savedScan is one scan read back off the disk.
type savedScan struct {
	Entry    report.ChainEntry
	Scan     report.Scan
	Verified bool   // the file still hashes to what the ledger recorded
	Err      string // set when the file could not be read or parsed
}

// Label names the scan in a list or a menu.
func (s *savedScan) Label() string {
	if s.Err != "" {
		return s.Entry.File + " (unreadable)"
	}
	return fmt.Sprintf("%s  %s", s.Scan.StartedAt.Format("2006-01-02 15:04:05"), s.Scan.Host)
}

// index is the list of scans in one folder that the dashboard may read.
type index struct {
	dir     string
	entries []report.ChainEntry
}

func readIndex(dir string) (*index, error) {
	entries, err := report.ReadChain(dir)
	if err != nil {
		return nil, fmt.Errorf("read evidence ledger: %w", err)
	}
	return &index{dir: dir, entries: entries}, nil
}

// load reads one scan by file name. The name must be listed in the ledger and
// must be a plain file name; anything else is errUnknownScan. A file that is
// listed but cannot be read or parsed comes back with Err set, so the page can
// say so instead of hiding the scan.
func (ix *index) load(file string) (*savedScan, error) {
	entry, ok := ix.entry(file)
	if !ok {
		return nil, errUnknownScan
	}
	s := &savedScan{Entry: entry}
	data, err := os.ReadFile(filepath.Join(ix.dir, entry.File))
	if err != nil {
		s.Err = "could not be read: " + err.Error()
		return s, nil
	}
	sum := sha256.Sum256(data)
	s.Verified = hex.EncodeToString(sum[:]) == entry.Hash
	if err := json.Unmarshal(data, &s.Scan); err != nil {
		s.Err = "is not readable as a saved scan: " + err.Error()
	}
	return s, nil
}

// entry finds the ledger line for a file name.
func (ix *index) entry(file string) (report.ChainEntry, bool) {
	if !plainFileName(file) {
		return report.ChainEntry{}, false
	}
	for _, e := range ix.entries {
		if e.File == file {
			return e, true
		}
	}
	return report.ChainEntry{}, false
}

// loadAll reads every scan the ledger lists, oldest first.
func (ix *index) loadAll() []*savedScan {
	out := make([]*savedScan, 0, len(ix.entries))
	for _, e := range ix.entries {
		s, err := ix.load(e.File)
		if err != nil {
			// The ledger line itself is unusable, which is worth showing.
			out = append(out, &savedScan{Entry: e, Err: err.Error()})
			continue
		}
		out = append(out, s)
	}
	return out
}

// latest returns the newest scan that could be read, and the one before it.
func latest(scans []*savedScan) (newest, previous *savedScan) {
	for i := len(scans) - 1; i >= 0; i-- {
		if scans[i].Err != "" {
			continue
		}
		if newest == nil {
			newest = scans[i]
			continue
		}
		return newest, scans[i]
	}
	return newest, nil
}

// plainFileName reports whether name is a bare file name: no directories, no
// drive, no walking upwards.
func plainFileName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) || filepath.IsAbs(name) || filepath.Base(name) != name {
		return false
	}
	return !strings.Contains(name, "..")
}

// computer is one row of the fleet overview.
type computer struct {
	Key      string // what the pages pass in ?host=
	Host     string // the computer, as its own evidence names it
	Label    string // from the host list, when it is listed there
	Local    bool
	Approved bool // named in the approved host list
	Scans    int
	Latest   *savedScan
	Stale    bool
	Since    string // how long ago the last scan was, in words
	ChainErr string
	Spark    template.HTML // the drift line the fleet table shows
}

// The states a computer can be in, worst first. The order is the order the
// fleet table sorts by, and the badge is read off the same list, so what the
// table says and how it sorts cannot drift apart.
const (
	StateNeverScanned = "NEVER SCANNED"
	StateUnreadable   = "UNREADABLE"
	StatePartial      = "PARTIAL"
	StateStale        = "STOPPED REPORTING"
	StateChainBroken  = "CHAIN BROKEN"
	StateUnverified   = "UNVERIFIED"
	StateCaptureGone  = "CAPTURE REJECTED"
	StateDrift        = "DRIFT"
	StateChanged      = "CHANGED"
	StateClean        = "CLEAN"
)

// stateOrder is how urgently each state needs looking at. A computer nobody has
// scanned, or that answered nothing, comes first; a scan that only half
// answered comes next, because a partly read computer is partly unknown; then a
// computer that stopped reporting, then evidence that does not hold up, then
// the findings themselves.
var stateOrder = []string{
	StateNeverScanned,
	StateUnreadable,
	StatePartial,
	StateStale,
	StateChainBroken,
	StateUnverified,
	StateCaptureGone,
	StateDrift,
	StateChanged,
	StateClean,
}

// Drift is the drift count of the last scan, or 0 when there is none.
func (c computer) Drift() int {
	if c.Latest == nil {
		return 0
	}
	return c.Latest.Scan.Summary.Drift
}

// Unreadable reports whether the last scan of this computer answered nothing at
// all, which is a different problem from finding drift.
func (c computer) Unreadable() bool {
	if c.Latest == nil {
		return false
	}
	s := c.Latest.Scan.Summary
	return s.Total > 0 && s.Errors == s.Total
}

// Partial reports whether the scan was saved but some checks could not be read:
// a remote scan cannot read audit policy, for instance, so part of the picture
// is missing even though the rest of it is fine. It is not drift, and it is not
// nothing.
func (c computer) Partial() bool {
	if c.Latest == nil || c.Unreadable() {
		return false
	}
	return c.Latest.Scan.Summary.Errors > 0
}

// State is the one word the fleet table shows for this computer.
func (c computer) State() string {
	switch {
	case c.Latest == nil:
		return StateNeverScanned
	case c.Unreadable():
		return StateUnreadable
	case c.ChainErr != "":
		return StateChainBroken
	case !c.Latest.Verified:
		return StateUnverified
	case c.Latest.Scan.CaptureStatus != "":
		return StateCaptureGone
	case c.Stale:
		return StateStale
	case c.Partial():
		return StatePartial
	case c.Drift() > 0:
		return StateDrift
	case c.Latest.Scan.Summary.Changed > 0:
		return StateChanged
	}
	return StateClean
}

// Attention is where this computer's state sits in the order above.
func (c computer) Attention() int {
	state := c.State()
	for i, s := range stateOrder {
		if s == state {
			return i
		}
	}
	return len(stateOrder)
}

// Settled reports whether there is nothing to do about this computer.
func (c computer) Settled() bool { return c.State() == StateClean }

// severityClass is the class a severity wears. The word itself is always
// printed beside it.
func severityClass(severity string) string {
	switch strings.ToLower(severity) {
	case "high", "medium", "low":
		return strings.ToLower(severity)
	}
	return ""
}

// fleet reads the latest state of every computer with evidence, plus every
// computer the host list approves that has none yet: a computer that was
// approved and never scanned is a gap, not an absence of news.
func (s *Server) fleet() []computer {
	var out []computer
	now := s.now()
	listed := s.approvedHosts()
	seen := map[string]bool{}

	for _, src := range s.sources() {
		c := computer{Key: src.Key, Local: src.Local, Host: src.Key}
		ix, err := readIndex(src.Dir)
		if err != nil {
			c.ChainErr = err.Error()
			out = append(out, c)
			continue
		}
		all := ix.loadAll()
		c.Scans = len(all)
		c.Latest, _ = latest(all)
		if c.Latest != nil {
			if c.Latest.Scan.Host != "" {
				c.Host = c.Latest.Scan.Host
			}
			age := now.Sub(c.Latest.Scan.StartedAt)
			c.Stale = age > staleAfter
			c.Since = since(age)
		}
		if c.Host == "" {
			c.Host = "this computer"
		}
		if listedHost, ok := listed[strings.ToLower(c.Host)]; ok {
			c.Label, c.Approved = listedHost.Label, true
		}
		// The line is drawn last, because which way it is coloured depends on
		// the state, and the state depends on everything above.
		c.Spark = sparkline(all, c.State() == StatePartial || c.State() == StateUnreadable)
		seen[strings.ToLower(c.Host)] = true
		out = append(out, c)
	}

	// A computer that was approved and never scanned is a gap, not an absence
	// of news. Its name is shown as the host list writes it, not as it was
	// looked up.
	for key, listedHost := range listed {
		if !seen[key] {
			out = append(out, computer{
				Key:      listedHost.Name,
				Host:     listedHost.Name,
				Label:    listedHost.Label,
				Approved: true,
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if a, b := out[i].Attention(), out[j].Attention(); a != b {
			return a < b
		}
		if a, b := out[i].Drift(), out[j].Drift(); a != b {
			return a > b
		}
		return strings.ToLower(out[i].Host) < strings.ToLower(out[j].Host)
	})
	return out
}

// since puts an age in words, because "4 days ago" is read faster than a
// timestamp when the question is whether a computer stopped reporting.
func since(age time.Duration) string {
	switch {
	case age < time.Minute:
		return "just now"
	case age < time.Hour:
		return fmt.Sprintf("%d min ago", int(age.Minutes()))
	case age < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(age.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(age.Hours()/24))
	}
}

// approvedHosts is the host list keyed by lowercased name, because Windows
// treats computer names case-insensitively, with each entry kept as written.
// It is empty when no list is configured; the dashboard will not scan a
// computer that is not in it.
func (s *Server) approvedHosts() map[string]fleet.Host {
	out := map[string]fleet.Host{}
	h, err := s.hosts()
	if err != nil {
		return out
	}
	for _, host := range h.Hosts {
		if !host.Skip {
			out[strings.ToLower(host.Name)] = host
		}
	}
	return out
}

// ledger is one hash chain under the results folder.
type ledger struct {
	Dir     string
	Kind    string // scan or capture
	Records int
	Err     string
}

// chainStatus is what report.Verify makes of every ledger it found.
type chainStatus struct {
	Ledgers  []ledger
	Records  int
	Problems int
}

// OK reports whether every ledger verified.
func (c chainStatus) OK() bool { return c.Problems == 0 && len(c.Ledgers) > 0 }

// Empty reports whether anything has been saved at all.
func (c chainStatus) Empty() bool { return len(c.Ledgers) == 0 }

// verifyChains re-runs the hash chain checks over every ledger in the results
// folder: the scans and captures of this computer, and of each computer with a
// folder of its own.
func (s *Server) verifyChains() chainStatus {
	var c chainStatus
	for _, src := range s.sources() {
		for _, pair := range []struct{ dir, kind string }{
			{src.Dir, "scan"},
			{captureFolder(src.Dir), "capture"},
		} {
			if _, err := os.Stat(filepath.Join(pair.dir, report.ChainLog)); err != nil {
				continue // nothing recorded here
			}
			l := ledger{Dir: pair.dir, Kind: pair.kind}
			n, err := report.Verify(pair.dir)
			l.Records = n
			if err != nil {
				l.Err = err.Error()
				c.Problems++
			}
			c.Records += n
			c.Ledgers = append(c.Ledgers, l)
		}
	}
	return c
}

// filter is the set of narrowing choices a scan page was asked for, taken from
// the query string. A value that is not one of the known ones is ignored, so
// the table and the form always agree about what is being shown.
type filter struct {
	Status   string
	Severity string
	Type     string
	Change   string // only CHANGED: "what moved since the capture" is its own question
}

var (
	knownStatus   = []string{compare.Drift, compare.Exception, compare.Error, compare.Compliant}
	knownSeverity = []string{"high", "medium", "low"}
	knownChange   = []string{compare.Changed}
	knownTypes    = []string{
		baseline.TypeRegistry, baseline.TypeService, baseline.TypeAccount, baseline.TypeGroup,
		baseline.TypeFirewall, baseline.TypeAudit, baseline.TypeSoftware,
	}
)

func pick(value string, known []string, normalize func(string) string) string {
	value = normalize(strings.TrimSpace(value))
	for _, k := range known {
		if k == value {
			return value
		}
	}
	return ""
}

// readFilter takes the narrowing choices out of a query string.
func readFilter(q map[string][]string) filter {
	first := func(key string) string {
		if v := q[key]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	return filter{
		Status:   pick(first("status"), knownStatus, strings.ToUpper),
		Severity: pick(first("severity"), knownSeverity, strings.ToLower),
		Type:     pick(first("type"), knownTypes, strings.ToLower),
		Change:   pick(first("change"), knownChange, strings.ToUpper),
	}
}

// Active reports whether anything is being hidden.
func (f filter) Active() bool {
	return f.Status != "" || f.Severity != "" || f.Type != "" || f.Change != ""
}

// match reports whether one result is in the filter. types maps a check ID to
// the type the baseline gives it, since a result does not record its own.
func (f filter) match(r compare.Result, types map[string]string) bool {
	if f.Status != "" && r.Status != f.Status {
		return false
	}
	if f.Severity != "" && !strings.EqualFold(r.Severity, f.Severity) {
		return false
	}
	if f.Type != "" && types[r.ID] != f.Type {
		return false
	}
	if f.Change != "" && r.Change != f.Change {
		return false
	}
	return true
}

// checkTypes maps check ID to type, for the type filter and the baseline page.
// A scan records no type of its own and the baseline may have moved on since,
// so a check the current baseline no longer lists has no type here.
func checkTypes(b *baseline.Baseline) map[string]string {
	types := map[string]string{}
	if b == nil {
		return types
	}
	for _, c := range b.Checks {
		types[c.ID] = c.Type
	}
	return types
}

// expiry describes how close an approved exception is to running out.
type expiry struct {
	Label string // ok, soon, expired
	Days  int    // days left; negative once it has expired
}

// expiringSoon is how far ahead the baseline page warns about an approval.
const expiringSoon = 30 * 24 * time.Hour

// exceptionExpiry works out whether an approval has run out, or is about to.
func exceptionExpiry(e baseline.Exception, now time.Time) expiry {
	on, err := e.ExpiresOn()
	if err != nil {
		return expiry{Label: "expired"}
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	left := on.Sub(today)
	days := int(left.Hours() / 24)
	switch {
	case left < 0:
		return expiry{Label: "expired", Days: days}
	case left <= expiringSoon:
		return expiry{Label: "soon", Days: days}
	}
	return expiry{Label: "ok", Days: days}
}
