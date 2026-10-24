// Package fleet reads the list of computers a scan is allowed to read.
//
// Reading another computer's configuration is the one thing this tool does that
// reaches off the machine it runs on, so the list is not just a convenience. It
// is the authorization record: it names who approved scanning these computers,
// when, for what, and until when, and it is the only way to name a target.
// There is no flag that scans an address, a range, or a wildcard, because a
// configuration scanner pointed at a network it was not approved for is just a
// reconnaissance tool.
package fleet

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ttran0012/winbaseline/internal/baseline"
)

// DateFormat is the date layout the host list uses, the same one the baseline
// uses for an exception's expiry.
const DateFormat = baseline.ExpiryFormat

// Hosts is a host list file.
type Hosts struct {
	Authorization Authorization `yaml:"authorization"`
	Hosts         []Host        `yaml:"hosts"`
}

// Authorization is the record of who approved these scans. Every field is
// required: a scan of someone else's server with nobody's name against it is
// exactly what this file exists to prevent.
type Authorization struct {
	ApprovedBy string `yaml:"approved_by"` // the person who authorized the scanning
	Approved   string `yaml:"approved"`    // the date they did, as YYYY-MM-DD
	Expires    string `yaml:"expires"`     // the last day the approval covers
	Scope      string `yaml:"scope"`       // what was approved, in their words
}

// Host is one computer to read.
type Host struct {
	Name     string `yaml:"name"`               // the computer name, as Windows knows it
	Label    string `yaml:"label,omitempty"`    // what it is, for the report
	Skip     bool   `yaml:"skip,omitempty"`     // listed and approved, but left out of this run
	Baseline string `yaml:"baseline,omitempty"` // a baseline file in the baseline folder; empty means choose by role
	Added    string `yaml:"added,omitempty"`    // the date it was put on the list
	AddedBy  string `yaml:"added_by,omitempty"` // who put it there
}

// hostName is what a computer name may look like: a NetBIOS name or a DNS name.
// No slashes, no wildcards, no addresses with ports, nothing that could be a
// path or a range.
var hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$`)

// Load reads a host list and checks that it authorizes anything at all. It does
// not check the per-host baseline fields, because it does not know the baseline
// folder; LoadFrom does.
func Load(path string) (*Hosts, error) {
	return LoadFrom(path, "")
}

// LoadFrom reads a host list and, when baselineFolder is given, also checks that
// every per-host baseline names a file in that folder which exists and loads.
// A host list is read this way wherever the baseline folder is known, so a
// mistyped or unreadable per-host baseline is caught the moment the list is
// read, not when that computer is finally scanned.
func LoadFrom(path, baselineFolder string) (*Hosts, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read host list: %w", err)
	}
	var h Hosts
	if err := yaml.Unmarshal(data, &h); err != nil {
		return nil, fmt.Errorf("parse host list: %w", err)
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	if baselineFolder != "" {
		if err := h.ValidateBaselines(baselineFolder); err != nil {
			return nil, err
		}
	}
	return &h, nil
}

// ValidateBaselines checks that every per-host baseline names a plain file in
// folder that exists and loads. A host with no baseline field is chosen for by
// role at scan time and needs nothing here.
func (h *Hosts) ValidateBaselines(folder string) error {
	for _, host := range h.Hosts {
		if host.Baseline == "" {
			continue
		}
		if !validBaselineName(host.Baseline) {
			return fmt.Errorf("host %q: baseline %q is not a plain file name in the baseline folder",
				host.Name, host.Baseline)
		}
		if _, err := baseline.Load(filepath.Join(folder, host.Baseline)); err != nil {
			return fmt.Errorf("host %q: baseline %q: %w", host.Name, host.Baseline, err)
		}
	}
	return nil
}

// Baselines returns the per-host baseline assignments, keyed by lowercased host
// name, for the scanner to resolve against. Hosts with no assignment are left
// out, to be chosen for by role.
func (h *Hosts) Baselines() map[string]string {
	out := map[string]string{}
	for _, host := range h.Hosts {
		if host.Baseline != "" {
			out[strings.ToLower(host.Name)] = host.Baseline
		}
	}
	return out
}

// validBaselineName rejects anything that is not a bare file name, so a host
// list cannot point the scanner at a file outside the baseline folder.
func validBaselineName(name string) bool {
	return name != "" && !strings.ContainsAny(name, `/\`) &&
		filepath.Base(name) == name && !strings.Contains(name, "..")
}

// Validate rejects a host list that does not record an approval, or that names
// something other than a computer.
func (h *Hosts) Validate() error {
	a := h.Authorization
	switch {
	case a.ApprovedBy == "":
		return fmt.Errorf("authorization: missing approved_by, which has to name the person who approved scanning these computers")
	case isPlaceholder(a.ApprovedBy):
		return fmt.Errorf("authorization: approved_by is still TODO")
	case a.Scope == "":
		return fmt.Errorf("authorization: missing scope, which has to say what was approved")
	case isPlaceholder(a.Scope):
		return fmt.Errorf("authorization: scope is still TODO")
	}
	if _, err := parseDate(a.Approved); err != nil {
		return fmt.Errorf("authorization: approved must be a date like 2026-01-31 (got %q)", a.Approved)
	}
	if _, err := parseDate(a.Expires); err != nil {
		return fmt.Errorf("authorization: expires must be a date like 2026-12-31 (got %q)", a.Expires)
	}

	// A list with no computers on it is allowed: it says the approval exists
	// and nothing has been added yet, which is where every list starts and
	// where one ends up when the last computer is removed. Targets is what
	// refuses to scan nothing.
	seen := map[string]bool{}
	for i, host := range h.Hosts {
		if host.Name == "" {
			return fmt.Errorf("host %d: missing name", i+1)
		}
		if !hostName.MatchString(host.Name) {
			return fmt.Errorf("host %q: not a computer name; a name or FQDN is expected, and ranges, "+
				"wildcards and addresses are not accepted", host.Name)
		}
		key := strings.ToLower(host.Name)
		if seen[key] {
			return fmt.Errorf("host %q: listed twice", host.Name)
		}
		seen[key] = true
	}
	return nil
}

// Authorized reports whether the approval covers today, so an approval that has
// run out stops the scanning instead of quietly carrying on.
func (h *Hosts) Authorized(now time.Time) error {
	expires, err := parseDate(h.Authorization.Expires)
	if err != nil {
		return fmt.Errorf("authorization: expires is not a date")
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if today.After(expires) {
		return fmt.Errorf("the approval to scan these computers expired on %s (approved by %s on %s); "+
			"renew it in the host list before scanning again",
			h.Authorization.Expires, h.Authorization.ApprovedBy, h.Authorization.Approved)
	}
	return nil
}

// Targets returns the computers this run should read, leaving out any marked
// skip. When only is given it selects that one computer, which has to be listed:
// a name nobody approved is not a target.
func (h *Hosts) Targets(only string) ([]Host, error) {
	if only != "" {
		for _, host := range h.Hosts {
			if strings.EqualFold(host.Name, only) {
				if host.Skip {
					return nil, fmt.Errorf("%s is marked skip in the host list", host.Name)
				}
				return []Host{host}, nil
			}
		}
		return nil, fmt.Errorf("%q is not in the host list, so scanning it has not been approved", only)
	}
	var out []Host
	for _, host := range h.Hosts {
		if !host.Skip {
			out = append(out, host)
		}
	}
	if len(out) == 0 {
		if len(h.Hosts) == 0 {
			return nil, fmt.Errorf("the host list names no computers yet")
		}
		return nil, fmt.Errorf("every computer in the list is marked skip")
	}
	return out, nil
}

// Allows reports whether a computer is in the list and not skipped. The
// dashboard asks this before it will start a scan of anything.
func (h *Hosts) Allows(name string) bool {
	for _, host := range h.Hosts {
		if strings.EqualFold(host.Name, name) && !host.Skip {
			return true
		}
	}
	return false
}

func parseDate(s string) (time.Time, error) {
	return time.Parse(baseline.ExpiryFormat, s)
}

// isPlaceholder catches an authorization nobody filled in, the same way the
// baseline catches an unfinished exception.
func isPlaceholder(v string) bool {
	return strings.EqualFold(strings.TrimSpace(v), baseline.Placeholder)
}
