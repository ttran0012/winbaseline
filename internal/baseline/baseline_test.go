package baseline

import (
	"strings"
	"testing"
)

func TestShippedBaselineIsValid(t *testing.T) {
	b, err := Load("../../baseline/windows11-baseline.yaml")
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, c := range b.Checks {
		types[c.Type]++
	}
	for _, want := range []string{TypeRegistry, TypeService, TypeAccount, TypeGroup, TypeFirewall, TypeAudit, TypeSoftware} {
		if types[want] == 0 {
			t.Errorf("baseline has no %s checks", want)
		}
	}
}

func TestValidateRejectsBadChecks(t *testing.T) {
	tests := []struct {
		name  string
		check Check
		want  string
	}{
		{"unknown type", Check{ID: "X", Severity: "low", Type: "printer"}, "unsupported type"},
		{"bad severity", Check{ID: "X", Severity: "urgent", Type: TypeService, Service: "x", Expected: "disabled"}, "severity"},
		{"service without name", Check{ID: "X", Severity: "low", Type: TypeService, Expected: "disabled"}, "service name"},
		{"audit without GUID", Check{ID: "X", Severity: "low", Type: TypeAudit, Subcategory: "Logon", Expected: "success"}, "GUID"},
		{"registry text value", Check{ID: "X", Severity: "low", Type: TypeRegistry, Hive: "HKLM", Path: "A", Value: "B", Operator: "equals", Expected: "on"}, "whole number"},
		{"group without approved list", Check{ID: "X", Severity: "low", Type: TypeGroup, Group: "administrators"}, "approved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := Baseline{Name: "test", Checks: []Check{tt.check}}
			err := b.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateExceptions(t *testing.T) {
	check := Check{ID: "SVC-001", Severity: "low", Type: TypeService, Service: "upnphost", Expected: "disabled"}
	approved := Exception{Check: "SVC-001", Reason: "vendor app needs it until migration", ApprovedBy: "J. Lee, IT Manager", Expires: "2026-12-31"}
	edit := func(f func(*Exception)) Exception {
		e := approved
		f(&e)
		return e
	}

	tests := []struct {
		name      string
		exception Exception
		want      string // error text expected; empty means the exception is accepted
	}{
		{"complete exception is accepted", approved, ""},
		{"host list is optional", edit(func(e *Exception) { e.Hosts = []string{"LAB-WIN11"} }), ""},
		{"missing check id", edit(func(e *Exception) { e.Check = "" }), "missing check id"},
		{"unknown check id", edit(func(e *Exception) { e.Check = "SVC-999" }), `no check with id "SVC-999"`},
		{"missing reason", edit(func(e *Exception) { e.Reason = "" }), "missing reason"},
		{"missing approved_by", edit(func(e *Exception) { e.ApprovedBy = "" }), "missing approved_by"},
		// A proposed exception arrives with placeholders a person has to replace.
		{"reason left as TODO", edit(func(e *Exception) { e.Reason = Placeholder }), "reason is still TODO"},
		{"reason left as todo in any case", edit(func(e *Exception) { e.Reason = "todo" }), "reason is still TODO"},
		{"reason left as TODO with stray spacing", edit(func(e *Exception) { e.Reason = "  ToDo  " }), "reason is still TODO"},
		{"approved_by left as TODO", edit(func(e *Exception) { e.ApprovedBy = Placeholder }), "approved_by is still TODO"},
		{"a reason that merely mentions a TODO is accepted",
			edit(func(e *Exception) { e.Reason = "TODO ticket IT-4821 tracks the replacement" }), ""},
		{"missing expiry date", edit(func(e *Exception) { e.Expires = "" }), "expires must be a date"},
		{"expiry in the wrong format", edit(func(e *Exception) { e.Expires = "31/12/2026" }), "expires must be a date"},
		{"expiry that is not a real day", edit(func(e *Exception) { e.Expires = "2026-02-30" }), "expires must be a date"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := Baseline{Name: "test", Checks: []Check{check}, Exceptions: []Exception{tt.exception}}
			err := b.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("Validate() = %v, want no error", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("Validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestExceptionCovers(t *testing.T) {
	tests := []struct {
		name      string
		exception Exception
		checkID   string
		host      string
		want      bool
	}{
		{"empty host list covers every host", Exception{Check: "SVC-001"}, "SVC-001", "LAB-WIN11", true},
		{"listed host is covered", Exception{Check: "SVC-001", Hosts: []string{"LAB-WIN11"}}, "SVC-001", "LAB-WIN11", true},
		{"host match ignores case", Exception{Check: "SVC-001", Hosts: []string{"lab-win11"}}, "SVC-001", "LAB-WIN11", true},
		{"host outside the list is not covered", Exception{Check: "SVC-001", Hosts: []string{"LAB-WIN10"}}, "SVC-001", "LAB-WIN11", false},
		{"one of several listed hosts", Exception{Check: "SVC-001", Hosts: []string{"LAB-WIN10", "LAB-WIN11"}}, "SVC-001", "LAB-WIN11", true},
		{"another check is not covered", Exception{Check: "SVC-001"}, "REG-001", "LAB-WIN11", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.exception.Covers(tt.checkID, tt.host); got != tt.want {
				t.Errorf("Covers(%q, %q) = %v, want %v", tt.checkID, tt.host, got, tt.want)
			}
		})
	}
}
