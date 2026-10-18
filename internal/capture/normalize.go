package capture

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
)

// Normalize turns a reading into the single line a capture records and later
// scans compare against. The same configuration always produces the same text:
// lists are sorted, because the order Windows happens to return group members
// or installed programs in is not a configuration change, and a value that
// could not be read is distinct from one that is not set, so an unreadable
// check is never mistaken for an approved absence.
func Normalize(chk baseline.Check, r collect.Reading) string {
	if r.Err != nil {
		// Only the state is recorded: the message varies with the cause, and a
		// differently worded failure is not a change in configuration.
		return "unreadable"
	}
	switch chk.Type {
	case baseline.TypeRegistry:
		if !r.Present {
			return "not set"
		}
		return fmt.Sprint(r.Num)
	case baseline.TypeService:
		if !r.Present {
			return "not installed"
		}
		return r.Text // start type: automatic, manual, disabled
	case baseline.TypeAccount:
		if !r.Present {
			return "not found"
		}
		state := "enabled"
		if r.Num == 1 {
			state = "disabled"
		}
		return fmt.Sprintf("%s as %s", state, r.Text)
	case baseline.TypeGroup:
		if len(r.List) == 0 {
			return "no members"
		}
		return strings.Join(sorted(r.List), ", ")
	case baseline.TypeFirewall:
		if !r.Present {
			return "not set"
		}
		state := "off"
		if r.Num == 1 {
			state = "on"
		}
		return fmt.Sprintf("%s (%s)", state, r.Text) // the source matters: policy or local
	case baseline.TypeAudit:
		if !r.Present {
			return "not reported"
		}
		return r.Text
	case baseline.TypeSoftware:
		if len(r.List) == 0 {
			return "not installed"
		}
		return strings.Join(sorted(r.List), ", ")
	}
	// A check type added without a case here still has to normalize to
	// something stable, or every scan would report it as changed.
	if !r.Present {
		return "not set"
	}
	return fmt.Sprintf("num=%d text=%s list=%s", r.Num, r.Text, strings.Join(sorted(r.List), ", "))
}

// sorted returns the list in a fixed order without disturbing the reading.
func sorted(list []string) []string {
	out := make([]string, len(list))
	copy(out, list)
	sort.Strings(out)
	return out
}
