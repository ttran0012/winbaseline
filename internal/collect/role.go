//go:build windows

package collect

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// A computer's role decides which baseline fits it when the host list does not
// name one. Windows reports the role as Win32_ComputerSystem.DomainRole, but
// that is a WMI value with no remote equivalent the collectors already reach.
// The registry does carry it, as ProductType under ProductOptions, and that is
// readable over the same remote-registry connection every other check uses, so
// a server or a domain controller can be told apart from a workstation without
// any new way of reaching the computer. ProductType maps onto the DomainRole
// numbers so the selection can be expressed in their terms.
const (
	RoleStandaloneWorkstation = 0
	RoleMemberWorkstation     = 1
	RoleStandaloneServer      = 2
	RoleMemberServer          = 3
	RoleBackupDC              = 4
	RolePrimaryDC             = 5
)

// productOptions is where Windows records what kind of installation this is.
const productOptions = `SYSTEM\CurrentControlSet\Control\ProductOptions`

// DomainRole reports the computer's role as one of the Role* values, read from
// the registry so it works locally and remotely alike. A domain controller
// reports a DC role, a server a member-server role, and everything else a
// workstation role.
func (c *Collector) DomainRole() (int, error) {
	productType, ok, err := c.registryString(productOptions, "ProductType")
	if err != nil {
		return 0, fmt.Errorf("read the product type of %s: %w", c.where(), err)
	}
	if !ok {
		return 0, fmt.Errorf("%s does not report a product type", c.where())
	}
	switch productType {
	case "LanmanNT":
		return RolePrimaryDC, nil
	case "ServerNT":
		return RoleMemberServer, nil
	case "WinNT":
		return RoleMemberWorkstation, nil
	}
	return 0, fmt.Errorf("%s reports an unfamiliar product type %q", c.where(), productType)
}

// registryString reads a string value under HKEY_LOCAL_MACHINE. ok is false
// when the key or value is simply not there, which is not an error.
func (c *Collector) registryString(path, name string) (value string, ok bool, err error) {
	k, err := c.openHKLM(path, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer k.Close()

	v, _, err := k.GetStringValue(name)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}
