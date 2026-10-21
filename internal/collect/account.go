//go:build windows

package collect

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserEnum             = netapi32.NewProc("NetUserEnum")
	procNetLocalGroupGetMembers = netapi32.NewProc("NetLocalGroupGetMembers")
)

const (
	filterNormalAccount = 0x0002
	maxPreferredLength  = 0xFFFFFFFF
	ufAccountDisable    = 0x0002
	ridAdministrator    = 500
	ridGuest            = 501
)

// userInfo20 mirrors USER_INFO_20.
type userInfo20 struct {
	Name     *uint16
	FullName *uint16
	Comment  *uint16
	Flags    uint32
	UserID   uint32
}

// localGroupMembersInfo3 mirrors LOCALGROUP_MEMBERS_INFO_3.
type localGroupMembersInfo3 struct {
	DomainAndName *uint16
}

// builtinAccount finds the built-in Guest or Administrator account by its
// well-known RID (so renamed accounts are still found) on the computer this
// collector reads. Num is 1 when the account is disabled; Text is the current
// account name.
func (c *Collector) builtinAccount(which string) Reading {
	rid := uint32(ridGuest)
	if which == "administrator" {
		rid = ridAdministrator
	}
	machine, err := c.machine()
	if err != nil {
		return Reading{Err: err}
	}

	var buf *byte
	var read, total, resume uint32
	// A nil machine name means this computer, which is what the call wants.
	r, _, _ := procNetUserEnum.Call(uintptr(unsafe.Pointer(machine)), 20, filterNormalAccount,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 {
		return Reading{Err: fmt.Errorf("list local accounts on %s: %w", c.where(), windows.Errno(r))}
	}
	defer windows.NetApiBufferFree(buf)

	for _, u := range unsafe.Slice((*userInfo20)(unsafe.Pointer(buf)), read) {
		if u.UserID == rid {
			disabled := uint64(0)
			if u.Flags&ufAccountDisable != 0 {
				disabled = 1
			}
			return Reading{Present: true, Num: disabled, Text: windows.UTF16PtrToString(u.Name)}
		}
	}
	return Reading{}
}

// administratorsMembers lists the members of the local Administrators group on
// the computer this collector reads. The group is found by its well-known SID,
// so this works on any Windows language.
func (c *Collector) administratorsMembers() Reading {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return Reading{Err: err}
	}
	// Resolve the group's name on the computer being read: an empty system
	// means this one.
	group, _, _, err := sid.LookupAccount(c.host)
	if err != nil {
		return Reading{Err: fmt.Errorf("find the Administrators group on %s: %w", c.where(), err)}
	}
	groupPtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return Reading{Err: err}
	}
	machine, err := c.machine()
	if err != nil {
		return Reading{Err: err}
	}

	var buf *byte
	var read, total, resume uint32
	r, _, _ := procNetLocalGroupGetMembers.Call(uintptr(unsafe.Pointer(machine)),
		uintptr(unsafe.Pointer(groupPtr)), 3,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 {
		return Reading{Err: fmt.Errorf("list Administrators members on %s: %w", c.where(), windows.Errno(r))}
	}
	defer windows.NetApiBufferFree(buf)

	var members []string
	for _, m := range unsafe.Slice((*localGroupMembersInfo3)(unsafe.Pointer(buf)), read) {
		members = append(members, windows.UTF16PtrToString(m.DomainAndName))
	}
	return Reading{Present: true, List: members, Text: group}
}
