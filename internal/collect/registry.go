//go:build windows

// Package collect reads current configuration values from the local system.
// All collectors are read-only.
package collect

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// Reading is the value observed on the system for one check.
type Reading struct {
	Present bool   // the value exists
	Value   uint64 // valid only when Present is true
	Err     error  // set when the value could not be read (e.g., access denied, wrong type)
}

// RegistryDWORD reads a DWORD/QWORD value under HKEY_LOCAL_MACHINE.
func RegistryDWORD(path, name string) Reading {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
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
	return Reading{Present: true, Value: v}
}
