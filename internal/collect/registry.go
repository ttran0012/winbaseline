//go:build windows

package collect

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// root is the HKEY_LOCAL_MACHINE this collector reads. A remote machine is
// connected to once per scan rather than once per check, so a computer that is
// switched off or unreachable fails once, quickly, with one clear reason
// instead of thirteen slow ones.
func (c *Collector) root() (registry.Key, error) {
	if c.host == "" {
		return registry.LOCAL_MACHINE, nil
	}
	if !c.loaded["hklm"] {
		c.hklm, c.hklmErr = registry.OpenRemoteKey(c.host, registry.LOCAL_MACHINE)
		if c.hklmErr != nil {
			c.hklmErr = fmt.Errorf("connect to the registry on %s: %w (is the computer reachable, "+
				"the Remote Registry service running, and this account allowed to read it?)", c.host, c.hklmErr)
		}
		c.loaded["hklm"] = true
	}
	return c.hklm, c.hklmErr
}

// openHKLM opens one key under HKEY_LOCAL_MACHINE for reading.
func (c *Collector) openHKLM(path string, access uint32) (registry.Key, error) {
	root, err := c.root()
	if err != nil {
		return 0, err
	}
	return registry.OpenKey(root, path, access)
}

// registryDWORD reads a DWORD/QWORD value under HKEY_LOCAL_MACHINE.
func (c *Collector) registryDWORD(path, name string) Reading {
	k, err := c.openHKLM(path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return Reading{}
	}
	if err != nil {
		return Reading{Err: fmt.Errorf("open key: %w", err)}
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return Reading{}
	}
	if err != nil {
		return Reading{Err: fmt.Errorf("read value: %w", err)}
	}
	return Reading{Present: true, Num: v}
}
