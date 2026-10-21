//go:build windows

package collect

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceStartType reads a service's start type (2 automatic, 3 manual,
// 4 disabled) from the computer this collector reads. Only connect and query
// rights are asked for, so this works without administrator rights locally and
// needs no more than read access remotely.
func (c *Collector) serviceStartType(name string) Reading {
	machine, err := c.machine()
	if err != nil {
		return Reading{Err: err}
	}
	scm, err := windows.OpenSCManager(machine, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Reading{Err: fmt.Errorf("open the service manager on %s: %w", c.where(), err)}
	}
	defer windows.CloseServiceHandle(scm)

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Reading{Err: err}
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_CONFIG)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return Reading{} // not installed
	}
	if err != nil {
		return Reading{Err: fmt.Errorf("open service: %w", err)}
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()

	cfg, err := s.Config()
	if err != nil {
		return Reading{Err: fmt.Errorf("query service: %w", err)}
	}
	return Reading{Present: true, Num: uint64(cfg.StartType), Text: startTypeName(cfg.StartType)}
}

// where names the computer being read, for error messages.
func (c *Collector) where() string {
	if c.host == "" {
		return "this computer"
	}
	return c.host
}

func startTypeName(t uint32) string {
	switch t {
	case windows.SERVICE_BOOT_START:
		return "boot"
	case windows.SERVICE_SYSTEM_START:
		return "system"
	case windows.SERVICE_AUTO_START:
		return "automatic"
	case windows.SERVICE_DEMAND_START:
		return "manual"
	case windows.SERVICE_DISABLED:
		return "disabled"
	}
	return fmt.Sprint(t)
}
