package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// commented is a host list written by a person: the comments carry the reasons,
// in every position a comment can sit.
const commented = `# Host list for driftscan -hosts.
# Copy this to hosts.yaml and fill it in.

# Who approved reading these computers, and until when.
authorization:
  approved_by: "J. Lee, IT Manager"   # the person who signed it off
  approved: "2026-10-01"
  expires: "2026-12-31"
  scope: "quarterly CIS review of the lab and file servers"

hosts:
  # The database server, moved to the new rack in September.
  - name: SQL-02
    label: "database server"   # finance reporting

  # Domain controller: read only during the maintenance window.
  - name: DC-01
    label: "domain controller"
    skip: true

# Nothing below this line yet.
`

func writeList(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The comments are where the reasons live, so an edit from the dashboard has to
// leave the person's file looking like their file.
func TestAddKeepsTheCommentsAndTheRestOfTheFile(t *testing.T) {
	path := writeList(t, commented)

	if err := Add(path, Host{Name: "FILE-03", Label: "file server"}, `LAB\itadmin`, today); err != nil {
		t.Fatal(err)
	}
	after := read(t, path)

	for _, comment := range []string{
		"# Host list for driftscan -hosts.",
		"# Who approved reading these computers, and until when.",
		"# the person who signed it off",
		"# The database server, moved to the new rack in September.",
		"# finance reporting",
		"# Domain controller: read only during the maintenance window.",
		"# Nothing below this line yet.",
	} {
		if !strings.Contains(after, comment) {
			t.Errorf("the edit lost this comment: %q\n\n%s", comment, after)
		}
	}

	// And the list itself is still right.
	h, err := Load(path)
	if err != nil {
		t.Fatalf("the edited file does not load: %v\n\n%s", err, after)
	}
	if len(h.Hosts) != 3 {
		t.Fatalf("hosts = %d, want 3", len(h.Hosts))
	}
	added := h.Hosts[2]
	switch {
	case added.Name != "FILE-03":
		t.Errorf("name = %q", added.Name)
	case added.Label != "file server":
		t.Errorf("label = %q", added.Label)
	case added.Added != today.Format(DateFormat):
		t.Errorf("added = %q, want %s", added.Added, today.Format(DateFormat))
	case added.AddedBy != `LAB\itadmin`:
		t.Errorf("added_by = %q", added.AddedBy)
	}
	// The computers that were already there are untouched, skip included.
	if h.Hosts[0].Name != "SQL-02" || h.Hosts[1].Name != "DC-01" || !h.Hosts[1].Skip {
		t.Errorf("the existing hosts changed: %+v", h.Hosts)
	}
}

// Every change keeps the file that was there before, and says who changed what.
func TestEditsKeepABackupAndALog(t *testing.T) {
	path := writeList(t, commented)
	if err := Add(path, Host{Name: "FILE-03"}, `LAB\itadmin`, today); err != nil {
		t.Fatal(err)
	}
	if backup := read(t, path+".bak"); backup != commented {
		t.Error("the .bak is not the file that was there before")
	}

	if err := SetSkip(path, "FILE-03", true, `LAB\itadmin`, today); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path, "SQL-02", `LAB\other`, today); err != nil {
		t.Fatal(err)
	}

	log := read(t, filepath.Join(filepath.Dir(path), ChangeLog))
	lines := strings.Split(strings.TrimSpace(log), "\n")
	if len(lines) != 3 {
		t.Fatalf("the log has %d lines, want 3:\n%s", len(lines), log)
	}
	for i, want := range []string{"added FILE-03", "left FILE-03 out of scans", "removed SQL-02"} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("log line %d = %q, want it to mention %q", i+1, lines[i], want)
		}
	}
	if !strings.Contains(lines[0], `LAB\itadmin`) || !strings.Contains(lines[2], `LAB\other`) {
		t.Errorf("the log does not record who made each change:\n%s", log)
	}
}

func TestSkipAndInclude(t *testing.T) {
	path := writeList(t, commented)
	if err := SetSkip(path, "sql-02", true, "tester", today); err != nil { // names are case-insensitive
		t.Fatal(err)
	}
	h, _ := Load(path)
	if !h.Hosts[0].Skip {
		t.Error("SQL-02 should be skipped")
	}
	if err := SetSkip(path, "SQL-02", false, "tester", today); err != nil {
		t.Fatal(err)
	}
	h, _ = Load(path)
	if h.Hosts[0].Skip {
		t.Error("SQL-02 should be back in scans")
	}
}

// Taking a computer off the list withdraws permission to read it. It is not a
// reason to lose the record of what it looked like.
func TestRemoveLeavesTheEvidenceAlone(t *testing.T) {
	path := writeList(t, commented)
	dir := filepath.Dir(path)
	evidence := filepath.Join(dir, "SQL-02")
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	scan := filepath.Join(evidence, "scan-SQL-02-20261001-080000-000.json")
	if err := os.WriteFile(scan, []byte(`{"host":"SQL-02"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Remove(path, "SQL-02", "tester", today); err != nil {
		t.Fatal(err)
	}
	h, _ := Load(path)
	if len(h.Hosts) != 1 || h.Hosts[0].Name != "DC-01" {
		t.Errorf("hosts = %+v, want only DC-01", h.Hosts)
	}
	if _, err := os.Stat(scan); err != nil {
		t.Errorf("removing a host deleted its evidence: %v", err)
	}
}

// Adding a computer is granting permission to read it, so it cannot be done
// while there is no approval in force.
func TestEditsRefusedWithoutAnApprovalInForce(t *testing.T) {
	tests := []struct {
		name string
		list string
		want string
	}{
		{"nobody approved it",
			strings.Replace(commented, `approved_by: "J. Lee, IT Manager"   # the person who signed it off`, `approved_by: ""`, 1),
			"approved_by"},
		{"the approval is still TODO",
			strings.Replace(commented, `approved_by: "J. Lee, IT Manager"   # the person who signed it off`, `approved_by: "TODO"`, 1),
			"TODO"},
		{"the scope is still TODO",
			strings.Replace(commented, `scope: "quarterly CIS review of the lab and file servers"`, `scope: "TODO"`, 1),
			"TODO"},
		{"the approval has expired",
			strings.Replace(commented, `expires: "2026-12-31"`, `expires: "2026-10-20"`, 1),
			"expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeList(t, tt.list)
			before := read(t, path)

			for what, err := range map[string]error{
				"add":    Add(path, Host{Name: "FILE-03"}, "tester", today),
				"skip":   SetSkip(path, "SQL-02", true, "tester", today),
				"remove": Remove(path, "SQL-02", "tester", today),
			} {
				if err == nil {
					t.Errorf("%s was allowed", what)
					continue
				}
				if !strings.Contains(err.Error(), tt.want) {
					t.Errorf("%s refused with %q, want it to mention %q", what, err, tt.want)
				}
			}
			if read(t, path) != before {
				t.Error("a refused change edited the file anyway")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), ChangeLog)); err == nil {
				t.Error("a refused change was written to the log")
			}
		})
	}
}

// The host list is the whole authorized scope, so it must not be possible to
// widen it with anything but one computer name at a time.
func TestCheckName(t *testing.T) {
	tests := []struct {
		name string
		ok   bool
	}{
		{"SQL-02", true},
		{"sql-02.corp.example.com", true},
		{"WIN11", true},
		{"a", true},
		{"10.0.0.5", true}, // a bare address is one computer; a mask or range is not

		{"", false},
		{" SQL-02", false},
		{"SQL-02 ", false},
		{"SQL-02 SQL-03", false},
		{"SQL-02,SQL-03", false},
		{"10.0.0.0/24", false},
		{"10.0.0.1-50", false},
		{"192.168.1.*", false},
		{"SQL-0?", false},
		{`\\SQL-02`, false},
		{"../SQL-02", false},
		{"SQL-02:445", false},
		{"-SQL-02", false},
		{"SQL-02-", false},
		{"SQL_02", false},
		{"sql 02", false},
		{strings.Repeat("a", 254), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckName(tt.name)
			if tt.ok && err != nil {
				t.Errorf("CheckName(%q) = %v, want it accepted", tt.name, err)
			}
			if !tt.ok && err == nil {
				t.Errorf("CheckName(%q) was accepted, want it refused", tt.name)
			}
		})
	}
}

func TestAddRefusesWhatTheListAlreadyHas(t *testing.T) {
	path := writeList(t, commented)
	if err := Add(path, Host{Name: "sql-02"}, "tester", today); err == nil ||
		!strings.Contains(err.Error(), "already on the list") {
		t.Errorf("Add = %v, want it refused as a duplicate", err)
	}
	if err := Add(path, Host{Name: "FILE-03", Label: "one\ntwo"}, "tester", today); err == nil {
		t.Error("a label spanning lines should be refused")
	}
}

func TestSkipAndRemoveNeedAComputerThatIsListed(t *testing.T) {
	path := writeList(t, commented)
	if err := SetSkip(path, "SQL-99", true, "tester", today); err == nil {
		t.Error("skipping a computer that is not listed should be refused")
	}
	if err := Remove(path, "SQL-99", "tester", today); err == nil {
		t.Error("removing a computer that is not listed should be refused")
	}
}
