//go:build windows

// Package collect reads current configuration values from a Windows computer.
// All collectors are read-only: they ask for values and never set them.
//
// A collector reads either this computer, or another one by name. Remote reads
// go through the Windows APIs that accept a machine name - the remote registry
// service, the service control manager, and the network management calls - so
// they authenticate as the account that is running the scan. This program
// stores no password, sends no credential of its own, and installs nothing on
// the computer being read. What it can see is exactly what that account is
// already allowed to see.
package collect

import (
	"fmt"
	"os"
	"os/user"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

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

// Collector reads checks from one computer. It caches the expensive queries -
// the remote registry connection, the audit policy, the installed software
// list - so each one happens once per scan.
type Collector struct {
	host string // the computer to read; empty means this one

	hklm     registry.Key
	hklmErr  error
	audit    map[string]string
	auditErr error
	software []string
	softErr  error
	loaded   map[string]bool
}

// New returns a collector that reads this computer.
func New() *Collector { return &Collector{loaded: map[string]bool{}} }

// NewRemote returns a collector that reads another computer by name, as the
// account running this process. Close it when the scan is done.
func NewRemote(host string) *Collector {
	return &Collector{host: host, loaded: map[string]bool{}}
}

// Host is the computer being read. Empty means this one.
func (c *Collector) Host() string { return c.host }

// Remote reports whether this collector reads another computer.
func (c *Collector) Remote() bool { return c.host != "" }

// Close releases the remote registry connection, if one was opened.
func (c *Collector) Close() error {
	if c.loaded["hklm"] && c.hklmErr == nil && c.host != "" {
		return c.hklm.Close()
	}
	return nil
}

// Read collects the current value for one check.
func (c *Collector) Read(chk baseline.Check) Reading {
	switch chk.Type {
	case baseline.TypeRegistry:
		return c.registryDWORD(chk.Path, chk.Value)
	case baseline.TypeService:
		return c.serviceStartType(chk.Service)
	case baseline.TypeAccount:
		return c.builtinAccount(chk.Account)
	case baseline.TypeGroup:
		return c.administratorsMembers()
	case baseline.TypeFirewall:
		return c.firewallProfile(chk.Profile)
	case baseline.TypeAudit:
		return c.auditSetting(chk.Subcategory)
	case baseline.TypeSoftware:
		return c.softwareMatching(chk.Pattern)
	}
	return Reading{Err: fmt.Errorf("no collector for type %q", chk.Type)}
}

// machine returns the \\server name for the Windows calls that take one, or
// nil for this computer.
func (c *Collector) machine() (*uint16, error) {
	if c.host == "" {
		return nil, nil
	}
	name, err := windows.UTF16PtrFromString(`\\` + c.host)
	if err != nil {
		return nil, fmt.Errorf("computer name %q cannot be used: %w", c.host, err)
	}
	return name, nil
}

// IsElevated reports whether the scan is running as an administrator. For a
// remote scan what matters is the rights the account holds on the computer
// being read, which only that computer can answer.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// CurrentUser returns the Windows account running the scan, for the record of
// who approved a capture and who a remote scan was run as. It falls back to the
// environment, and then to a plain label, because not knowing who ran it is no
// reason to fail a capture.
func CurrentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if name := os.Getenv("USERNAME"); name != "" {
		return name
	}
	return "unknown"
}
