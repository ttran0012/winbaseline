package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var today = time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)

func authorized() Authorization {
	return Authorization{
		ApprovedBy: "J. Lee, IT Manager",
		Approved:   "2026-10-01",
		Expires:    "2026-12-31",
		Scope:      "quarterly CIS review of the lab and file servers",
	}
}

func list(hosts ...Host) *Hosts {
	return &Hosts{Authorization: authorized(), Hosts: hosts}
}

func TestValidate(t *testing.T) {
	edit := func(f func(*Hosts)) *Hosts {
		h := list(Host{Name: "SQL-02"})
		f(h)
		return h
	}

	tests := []struct {
		name  string
		hosts *Hosts
		want  string // expected error text; empty means accepted
	}{
		{"a complete list is accepted", list(Host{Name: "SQL-02", Label: "database"}), ""},
		{"an FQDN is a computer name", list(Host{Name: "sql-02.corp.example.com"}), ""},

		// A list with an approval and no computers yet is valid; it is Targets
		// that refuses to scan nothing.
		{"an approval with no computers yet", edit(func(h *Hosts) { h.Hosts = nil }), ""},
		{"a host with no name", edit(func(h *Hosts) { h.Hosts[0].Name = "" }), "missing name"},
		{"the same host twice", edit(func(h *Hosts) {
			h.Hosts = append(h.Hosts, Host{Name: "sql-02"})
		}), "listed twice"},

		// Nothing that could widen a scan beyond the computers named here.
		{"a wildcard", edit(func(h *Hosts) { h.Hosts[0].Name = "SQL-*" }), "not a computer name"},
		{"an address range", edit(func(h *Hosts) { h.Hosts[0].Name = "10.0.0.0/24" }), "not a computer name"},
		{"a UNC path", edit(func(h *Hosts) { h.Hosts[0].Name = `\\SQL-02` }), "not a computer name"},
		{"a name with a port", edit(func(h *Hosts) { h.Hosts[0].Name = "SQL-02:445" }), "not a computer name"},
		{"a path", edit(func(h *Hosts) { h.Hosts[0].Name = "../SQL-02" }), "not a computer name"},

		// The approval has to be a real record of a real decision.
		{"nobody approved it", edit(func(h *Hosts) { h.Authorization.ApprovedBy = "" }), "missing approved_by"},
		{"approved_by left as TODO", edit(func(h *Hosts) { h.Authorization.ApprovedBy = "TODO" }), "still TODO"},
		{"no scope", edit(func(h *Hosts) { h.Authorization.Scope = "" }), "missing scope"},
		{"scope left as TODO", edit(func(h *Hosts) { h.Authorization.Scope = "todo" }), "still TODO"},
		{"no approval date", edit(func(h *Hosts) { h.Authorization.Approved = "" }), "approved must be a date"},
		{"a bad approval date", edit(func(h *Hosts) { h.Authorization.Approved = "01/10/2026" }), "approved must be a date"},
		{"no expiry", edit(func(h *Hosts) { h.Authorization.Expires = "" }), "expires must be a date"},
		{"an expiry that is not a real day", edit(func(h *Hosts) { h.Authorization.Expires = "2026-02-30" }), "expires must be a date"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.hosts.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("Validate() = %v, want no error", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("Validate() = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

// An approval with no end date would be a standing permission to read other
// people's servers, so it has one, and it is enforced.
func TestAuthorized(t *testing.T) {
	tests := []struct {
		name    string
		expires string
		ok      bool
	}{
		{"well within the approval", "2026-12-31", true},
		{"the last approved day", "2026-10-21", true},
		{"the day after it lapsed", "2026-10-20", false},
		{"long expired", "2025-01-01", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := list(Host{Name: "SQL-02"})
			h.Authorization.Expires = tt.expires
			err := h.Authorized(today)
			if tt.ok && err != nil {
				t.Errorf("Authorized() = %v, want the scan allowed", err)
			}
			if !tt.ok {
				if err == nil {
					t.Fatal("Authorized() allowed a scan after the approval expired")
				}
				for _, want := range []string{"expired", "J. Lee, IT Manager"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("the refusal should mention %q, got %q", want, err)
					}
				}
			}
		})
	}
}

func TestTargets(t *testing.T) {
	h := list(
		Host{Name: "SQL-02"},
		Host{Name: "DC-01", Skip: true},
		Host{Name: "FILE-03"},
	)

	all, err := h.Targets("")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Name != "SQL-02" || all[1].Name != "FILE-03" {
		t.Errorf("Targets() = %v, want the two hosts that are not skipped", all)
	}

	one, err := h.Targets("file-03") // Windows names are case-insensitive
	if err != nil || len(one) != 1 || one[0].Name != "FILE-03" {
		t.Errorf("Targets(file-03) = %v, %v; want just FILE-03", one, err)
	}

	// A computer nobody approved cannot be reached by naming it on the command line.
	if _, err := h.Targets("SQL-99"); err == nil || !strings.Contains(err.Error(), "not been approved") {
		t.Errorf("Targets(SQL-99) = %v, want it refused as unapproved", err)
	}
	if _, err := h.Targets("DC-01"); err == nil || !strings.Contains(err.Error(), "skip") {
		t.Errorf("Targets(DC-01) = %v, want it refused as skipped", err)
	}

	// Nothing listed, or everything skipped, is nothing to scan.
	empty := list()
	if _, err := empty.Targets(""); err == nil || !strings.Contains(err.Error(), "no computers yet") {
		t.Errorf("Targets on an empty list = %v, want it refused", err)
	}
	allSkipped := list(Host{Name: "SQL-02", Skip: true})
	if _, err := allSkipped.Targets(""); err == nil || !strings.Contains(err.Error(), "skip") {
		t.Errorf("Targets with everything skipped = %v, want it refused", err)
	}
}

func TestAllows(t *testing.T) {
	h := list(Host{Name: "SQL-02"}, Host{Name: "DC-01", Skip: true})
	tests := map[string]bool{
		"SQL-02": true,
		"sql-02": true,
		"DC-01":  false, // skipped
		"SQL-99": false, // not listed
		"":       false,
	}
	for name, want := range tests {
		if got := h.Allows(name); got != want {
			t.Errorf("Allows(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yaml")
	const file = `
authorization:
  approved_by: "J. Lee, IT Manager"
  approved: "2026-10-01"
  expires: "2026-12-31"
  scope: "quarterly CIS review of the lab and file servers"

hosts:
  - name: SQL-02
    label: "database server"
  - name: DC-01
    label: "domain controller"
    skip: true
`
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if h.Authorization.ApprovedBy != "J. Lee, IT Manager" || h.Authorization.Scope == "" {
		t.Errorf("authorization = %+v", h.Authorization)
	}
	if len(h.Hosts) != 2 || h.Hosts[0].Label != "database server" || !h.Hosts[1].Skip {
		t.Errorf("hosts = %+v", h.Hosts)
	}

	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("loading a missing host list should fail")
	}
}

func TestLoadRejectsAFileWithNoApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yaml")
	if err := os.WriteFile(path, []byte("hosts:\n  - name: SQL-02\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "approved_by") {
		t.Errorf("Load() = %v, want it to refuse a list with no approval", err)
	}
}
