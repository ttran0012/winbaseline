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

// BuiltinAccount finds the built-in Guest or Administrator account by its
// well-known RID (so renamed accounts are still found). Num is 1 when the
// account is disabled; Text is the current account name.
func BuiltinAccount(which string) Reading {
	rid := uint32(ridGuest)
	if which == "administrator" {
		rid = ridAdministrator
	}

	var buf *byte
	var read, total, resume uint32
	r, _, _ := procNetUserEnum.Call(0, 20, filterNormalAccount,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 {
		return Reading{Err: fmt.Errorf("list local accounts: %w", windows.Errno(r))}
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

// AdministratorsMembers lists the members of the local Administrators group.
// The group is found by its well-known SID, so this works on any Windows language.
func AdministratorsMembers() Reading {
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return Reading{Err: err}
	}
	group, _, _, err := sid.LookupAccount("")
	if err != nil {
		return Reading{Err: fmt.Errorf("find Administrators group: %w", err)}
	}
	groupPtr, err := windows.UTF16PtrFromString(group)
	if err != nil {
		return Reading{Err: err}
	}

	var buf *byte
	var read, total, resume uint32
	r, _, _ := procNetLocalGroupGetMembers.Call(0, uintptr(unsafe.Pointer(groupPtr)), 3,
		uintptr(unsafe.Pointer(&buf)), maxPreferredLength,
		uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&resume)))
	if r != 0 {
		return Reading{Err: fmt.Errorf("list Administrators members: %w", windows.Errno(r))}
	}
	defer windows.NetApiBufferFree(buf)

	var members []string
	for _, m := range unsafe.Slice((*localGroupMembersInfo3)(unsafe.Pointer(buf)), read) {
		members = append(members, windows.UTF16PtrToString(m.DomainAndName))
	}
	return Reading{Present: true, List: members, Text: group}
}
