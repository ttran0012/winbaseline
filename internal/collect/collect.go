//go:build windows

// Package collect reads current configuration values from the local system.
// All collectors are read-only.
package collect

import (
	"fmt"
	"os"
	"os/user"

	"golang.org/x/sys/windows"

	"github.com/ttran0012/winbaseline/internal/baseline"
)

// Reading is what was observed on the system for one check.
type Reading struct {
	Present bool     // the setting, service, or account exists
	Num     uint64   // numeric value (registry, service start type, firewall state, account disabled flag)
	Text    string   // text value (account name, audit setting, value source)
	List    []string // list value (group members, matching software)
	Err     error    // set when the value could not be read
}

// Collector reads checks. It caches expensive system queries (audit policy,
// installed software) so they run once per scan.
type Collector struct {
	audit    map[string]string
	auditErr error
	software []string
	softErr  error
	loaded   map[string]bool
}

// New returns an empty collector.
func New() *Collector { return &Collector{loaded: map[string]bool{}} }

// Read collects the current value for one check.
func (c *Collector) Read(chk baseline.Check) Reading {
	switch chk.Type {
	case baseline.TypeRegistry:
		return RegistryDWORD(chk.Path, chk.Value)
	case baseline.TypeService:
		return ServiceStartType(chk.Service)
	case baseline.TypeAccount:
		return BuiltinAccount(chk.Account)
	case baseline.TypeGroup:
		return AdministratorsMembers()
	case baseline.TypeFirewall:
		return FirewallProfile(chk.Profile)
	case baseline.TypeAudit:
		return c.auditSetting(chk.Subcategory)
	case baseline.TypeSoftware:
		return c.softwareMatching(chk.Pattern)
	}
	return Reading{Err: fmt.Errorf("no collector for type %q", chk.Type)}
}

// IsElevated reports whether the scan is running as an administrator.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// CurrentUser returns the Windows account running the scan, for the record of
// who approved a capture. It falls back to the environment, and then to a plain
// label, because not knowing who ran it is no reason to fail a capture.
func CurrentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if name := os.Getenv("USERNAME"); name != "" {
		return name
	}
	return "unknown"
}
