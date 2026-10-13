//go:build windows

package collect

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

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
	return Reading{Present: true, Num: v}
}
