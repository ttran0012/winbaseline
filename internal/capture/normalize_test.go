package capture

import (
	"errors"
	"testing"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
)

var (
	regCheck  = baseline.Check{ID: "REG-001", Type: baseline.TypeRegistry}
	svcCheck  = baseline.Check{ID: "SVC-001", Type: baseline.TypeService}
	acctCheck = baseline.Check{ID: "ACCT-001", Type: baseline.TypeAccount}
	grpCheck  = baseline.Check{ID: "GRP-001", Type: baseline.TypeGroup}
	fwCheck   = baseline.Check{ID: "FW-001", Type: baseline.TypeFirewall}
	audCheck  = baseline.Check{ID: "AUD-001", Type: baseline.TypeAudit}
	swCheck   = baseline.Check{ID: "SW-001", Type: baseline.TypeSoftware}
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name  string
		check baseline.Check
		read  collect.Reading
		want  string
	}{
		{"registry value", regCheck, collect.Reading{Present: true, Num: 1}, "1"},
		{"registry zero is a value, not an absence", regCheck, collect.Reading{Present: true, Num: 0}, "0"},
		{"registry not configured", regCheck, collect.Reading{}, "not set"},
		{"registry unreadable", regCheck, collect.Reading{Err: errors.New("access denied")}, "unreadable"},

		{"service start type", svcCheck, collect.Reading{Present: true, Num: 3, Text: "manual"}, "manual"},
		{"service not installed", svcCheck, collect.Reading{}, "not installed"},

		{"account disabled", acctCheck, collect.Reading{Present: true, Num: 1, Text: "Guest"}, "disabled as Guest"},
		{"account enabled", acctCheck, collect.Reading{Present: true, Num: 0, Text: "Guest"}, "enabled as Guest"},
		{"account renamed", acctCheck, collect.Reading{Present: true, Num: 0, Text: "locadm"}, "enabled as locadm"},
		{"account missing", acctCheck, collect.Reading{}, "not found"},

		{"group members are sorted", grpCheck,
			collect.Reading{Present: true, List: []string{`PC1\itadmin`, `PC1\Administrator`}},
			`PC1\Administrator, PC1\itadmin`},
		{"group with no members", grpCheck, collect.Reading{Present: true}, "no members"},

		{"firewall on", fwCheck, collect.Reading{Present: true, Num: 1, Text: "local setting"}, "on (local setting)"},
		{"firewall off", fwCheck, collect.Reading{Present: true, Num: 0, Text: "group policy"}, "off (group policy)"},
		{"firewall not set", fwCheck, collect.Reading{}, "not set"},

		{"audit setting", audCheck, collect.Reading{Present: true, Text: "Success and Failure"}, "Success and Failure"},
		{"audit not reported", audCheck, collect.Reading{}, "not reported"},
		{"audit needs administrator", audCheck, collect.Reading{Err: errors.New("auditpol: access denied")}, "unreadable"},

		{"matching software is sorted", swCheck,
			collect.Reading{Present: true, List: []string{"uTorrent", "AnyDesk"}}, "AnyDesk, uTorrent"},
		{"no matching software", swCheck, collect.Reading{}, "not installed"},

		{"a type with no case still normalizes", baseline.Check{ID: "X", Type: "printer"},
			collect.Reading{Present: true, Num: 2, Text: "shared"}, "num=2 text=shared list="},
		{"a type with no case, nothing present", baseline.Check{ID: "X", Type: "printer"},
			collect.Reading{}, "not set"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Normalize(tt.check, tt.read); got != tt.want {
				t.Errorf("Normalize() = %q, want %q", got, tt.want)
			}
		})
	}
}

// The order Windows returns group members or installed programs in is not a
// configuration change, so it must not read as one.
func TestNormalizeIgnoresListOrder(t *testing.T) {
	members := []string{`PC1\Administrator`, `PC1\itadmin`, `PC1\locadm`}
	shuffled := []string{`PC1\locadm`, `PC1\Administrator`, `PC1\itadmin`}

	for _, chk := range []baseline.Check{grpCheck, swCheck} {
		t.Run(chk.Type, func(t *testing.T) {
			first := Normalize(chk, collect.Reading{Present: true, List: members})
			second := Normalize(chk, collect.Reading{Present: true, List: shuffled})
			if first != second {
				t.Errorf("same list in a different order normalized to %q and %q", first, second)
			}
			// A member that really was added still has to show up as different.
			added := Normalize(chk, collect.Reading{Present: true, List: append(append([]string{}, members...), `PC1\vendor`)})
			if added == first {
				t.Errorf("an added member normalized to the same value %q", added)
			}
		})
	}
}

// A setting nobody configured and a setting the scan could not read are two
// different facts; recording both as "missing" would let an unreadable check be
// approved as an absence.
func TestNormalizeDistinguishesNotSetFromUnreadable(t *testing.T) {
	notSet := Normalize(regCheck, collect.Reading{})
	unreadable := Normalize(regCheck, collect.Reading{Err: errors.New("access denied")})
	if notSet == unreadable {
		t.Fatalf("not set and unreadable both normalized to %q", notSet)
	}
}

// The same reading always has to produce the same text, whatever the error says.
func TestNormalizeIsStableAcrossDifferentErrorMessages(t *testing.T) {
	first := Normalize(audCheck, collect.Reading{Err: errors.New("auditpol: access denied")})
	second := Normalize(audCheck, collect.Reading{Err: errors.New("auditpol: exit status 1")})
	if first != second {
		t.Errorf("two failures normalized to %q and %q", first, second)
	}
}

// Normalize must not reorder the reading it was handed: the scan reports the
// values in the order the system gave them.
func TestNormalizeLeavesTheReadingAlone(t *testing.T) {
	list := []string{"uTorrent", "AnyDesk"}
	Normalize(swCheck, collect.Reading{Present: true, List: list})
	if list[0] != "uTorrent" {
		t.Errorf("Normalize sorted the caller's list: %v", list)
	}
}
