package compare

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
)

func u(v uint64) *uint64 { return &v }

func TestEvaluate(t *testing.T) {
	eq := baseline.Check{ID: "T-1", Type: "registry", Operator: "equals", Expected: "1", Hive: "HKLM", Path: `A\B`, Value: "V"}
	lte := baseline.Check{ID: "T-2", Type: "registry", Operator: "lte", Expected: "900", Hive: "HKLM", Path: `A\B`, Value: "V"}
	withDefault := eq
	withDefault.Default = u(1)
	svc := baseline.Check{ID: "S-1", Type: "service", Service: "upnphost", Expected: "disabled_or_absent"}
	svcStrict := svc
	svcStrict.Expected = "disabled"
	guest := baseline.Check{ID: "A-1", Type: "account", Account: "guest", Expected: "disabled"}
	admin := baseline.Check{ID: "A-2", Type: "account", Account: "administrator", Expected: "renamed"}
	group := baseline.Check{ID: "G-1", Type: "group", Group: "administrators", Approved: []string{"Administrator", "itadmin"}}
	fw := baseline.Check{ID: "F-1", Type: "firewall", Profile: "public", Expected: "on"}
	audit := baseline.Check{ID: "AU-1", Type: "audit", Expected: "success_and_failure"}
	auditSuccess := audit
	auditSuccess.Expected = "success"
	sw := baseline.Check{ID: "SW-1", Type: "software", Pattern: "(?i)torrent", Expected: "absent"}

	tests := []struct {
		name  string
		check baseline.Check
		read  collect.Reading
		want  string
	}{
		{"registry equal value is compliant", eq, collect.Reading{Present: true, Num: 1}, Compliant},
		{"registry different value is drift", eq, collect.Reading{Present: true, Num: 0}, Drift},
		{"registry missing value without default is drift", eq, collect.Reading{}, Drift},
		{"registry missing value uses secure default", withDefault, collect.Reading{}, Compliant},
		{"registry lte below limit is compliant", lte, collect.Reading{Present: true, Num: 600}, Compliant},
		{"registry lte above limit is drift", lte, collect.Reading{Present: true, Num: 1800}, Drift},
		{"read error is reported", eq, collect.Reading{Err: errors.New("access denied")}, Error},

		{"service disabled is compliant", svc, collect.Reading{Present: true, Num: 4, Text: "disabled"}, Compliant},
		{"service manual is drift", svc, collect.Reading{Present: true, Num: 3, Text: "manual"}, Drift},
		{"service not installed is compliant when absence allowed", svc, collect.Reading{}, Compliant},
		{"service not installed is drift when it must exist disabled", svcStrict, collect.Reading{}, Drift},

		{"guest disabled is compliant", guest, collect.Reading{Present: true, Num: 1, Text: "Guest"}, Compliant},
		{"guest enabled is drift", guest, collect.Reading{Present: true, Num: 0, Text: "Guest"}, Drift},
		{"administrator renamed is compliant", admin, collect.Reading{Present: true, Text: "locadm"}, Compliant},
		{"administrator not renamed is drift", admin, collect.Reading{Present: true, Text: "Administrator"}, Drift},

		{"approved admins are compliant", group, collect.Reading{Present: true, List: []string{`PC1\Administrator`, `PC1\itadmin`}}, Compliant},
		{"leftover vendor admin is drift", group, collect.Reading{Present: true, List: []string{`PC1\Administrator`, `PC1\vendor`}}, Drift},

		{"firewall on is compliant", fw, collect.Reading{Present: true, Num: 1, Text: "local setting"}, Compliant},
		{"firewall off is drift", fw, collect.Reading{Present: true, Num: 0, Text: "local setting"}, Drift},

		{"audit success and failure is compliant", audit, collect.Reading{Present: true, Text: "Success and Failure"}, Compliant},
		{"audit success only is drift when both required", audit, collect.Reading{Present: true, Text: "Success"}, Drift},
		{"audit no auditing is drift", auditSuccess, collect.Reading{Present: true, Text: "No Auditing"}, Drift},
		{"audit success satisfies success", auditSuccess, collect.Reading{Present: true, Text: "Success and Failure"}, Compliant},

		{"prohibited software absent is compliant", sw, collect.Reading{}, Compliant},
		{"prohibited software installed is drift", sw, collect.Reading{Present: true, List: []string{"uTorrent"}}, Drift},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Evaluate(tt.check, tt.read).Status; got != tt.want {
				t.Errorf("status = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestApplyExceptions(t *testing.T) {
	// A fixed "today" keeps the expiry cases from depending on the real date.
	today := time.Date(2026, 10, 18, 14, 30, 0, 0, time.Local)
	const host = "LAB-WIN11"

	approved := baseline.Exception{
		Check:      "SVC-001",
		Reason:     "vendor app needs the service until migration",
		ApprovedBy: "J. Lee, IT Manager",
		Expires:    "2026-12-31",
	}
	edit := func(f func(*baseline.Exception)) []baseline.Exception {
		e := approved
		f(&e)
		return []baseline.Exception{e}
	}
	drift := Result{ID: "SVC-001", Status: Drift}

	tests := []struct {
		name       string
		result     Result
		exceptions []baseline.Exception
		host       string
		wantStatus string
		wantNote   string // substring the note must contain; empty means the note is unchanged
	}{
		{"drift becomes an exception", drift, []baseline.Exception{approved}, host, Exception,
			"approved exception: vendor app needs the service until migration (approved by J. Lee, IT Manager, expires 2026-12-31)"},
		{"no exceptions leaves drift alone", drift, nil, host, Drift, ""},
		{"exception for another check leaves drift alone", drift,
			edit(func(e *baseline.Exception) { e.Check = "SVC-002" }), host, Drift, ""},

		{"exception expiring today still applies", drift,
			edit(func(e *baseline.Exception) { e.Expires = "2026-10-18" }), host, Exception, "approved exception:"},
		{"exception that expired yesterday does not apply", drift,
			edit(func(e *baseline.Exception) { e.Expires = "2026-10-17" }), host, Drift,
			"approved exception expired on 2026-10-17"},
		{"expiry note names the reason and approver", drift,
			edit(func(e *baseline.Exception) { e.Expires = "2025-01-01" }), host, Drift,
			"(approved by J. Lee, IT Manager)"},

		{"empty host list covers this host", drift, []baseline.Exception{approved}, host, Exception, "approved exception:"},
		{"listed host is covered", drift,
			edit(func(e *baseline.Exception) { e.Hosts = []string{"LAB-WIN10", "LAB-WIN11"} }), host, Exception, "approved exception:"},
		{"host match ignores case", drift,
			edit(func(e *baseline.Exception) { e.Hosts = []string{"lab-win11"} }), host, Exception, "approved exception:"},
		{"host outside the list keeps the drift", drift,
			edit(func(e *baseline.Exception) { e.Hosts = []string{"LAB-WIN10"} }), host, Drift, ""},

		{"compliant results are never changed", Result{ID: "SVC-001", Status: Compliant},
			[]baseline.Exception{approved}, host, Compliant, ""},
		{"error results are never changed", Result{ID: "SVC-001", Status: Error, Note: "access denied"},
			[]baseline.Exception{approved}, host, Error, ""},

		{"the note the check produced is kept", Result{ID: "SVC-001", Status: Drift, Note: "setting is not configured"},
			[]baseline.Exception{approved}, host, Exception, "setting is not configured; approved exception:"},
		{"an exception in force wins over an expired one", drift,
			[]baseline.Exception{
				{Check: "SVC-001", Reason: "old approval", ApprovedBy: "A. Nguyen", Expires: "2026-01-31"},
				approved,
			}, host, Exception, "approved exception: vendor app needs the service"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyExceptions(tt.result, tt.exceptions, tt.host, today)
			if got.Status != tt.wantStatus {
				t.Errorf("status = %s, want %s", got.Status, tt.wantStatus)
			}
			if tt.wantNote == "" {
				if got.Note != tt.result.Note {
					t.Errorf("note = %q, want it unchanged (%q)", got.Note, tt.result.Note)
				}
				return
			}
			if !strings.Contains(got.Note, tt.wantNote) {
				t.Errorf("note = %q, want it to contain %q", got.Note, tt.wantNote)
			}
		})
	}
}
