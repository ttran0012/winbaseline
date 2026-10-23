package serve

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ttran0012/winbaseline/internal/fleet"
)

// commentedList is a host list as a person writes one: the comments carry the
// reasons for the entries.
const commentedList = `# The computers we are approved to read.
authorization:
  approved_by: "J. Lee, IT Manager"
  approved: "2026-10-01"
  expires: "2026-12-31"
  scope: "quarterly CIS review of the lab"

hosts:
  # Moved to the new rack in September.
  - name: SQL-02
    label: "database server"
`

// manageServer is a dashboard with a real host list it may change.
func manageServer(t *testing.T, list string) (*Server, string) {
	t.Helper()
	s, _ := testServer(t)
	path := filepath.Join(s.dir, "hosts.yaml")
	if err := os.WriteFile(path, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	s.hostsPath = path
	return s, path
}

func postTo(t *testing.T, s *Server, path string, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	return postPath(t, s, path, form, headers)
}

// A host list change is a change to the authorized scope, so it needs the same
// proof of origin as starting a scan.
func TestHostChangesNeedATrustedForm(t *testing.T) {
	s, path := manageServer(t, commentedList)
	before := readFile(t, path)

	for _, target := range []string{addHostPath, skipHostPath, removeHostPath, testHostPath} {
		t.Run(target, func(t *testing.T) {
			for _, bad := range []struct {
				name    string
				form    url.Values
				headers map[string]string
			}{
				{"no token", url.Values{"name": {"WS03"}, "confirm": {"1"}}, nil},
				{"wrong token", url.Values{"name": {"WS03"}, "confirm": {"1"}, "csrf": {"nope"}}, nil},
				{"another site", url.Values{"name": {"WS03"}, "confirm": {"1"}, "csrf": {s.csrf}},
					map[string]string{"Sec-Fetch-Site": "cross-site"}},
			} {
				rec := postTo(t, s, target, bad.form, bad.headers)
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s with %s = %d, want 403", target, bad.name, rec.Code)
				}
			}
		})
	}
	if readFile(t, path) != before {
		t.Error("a refused request changed the host list anyway")
	}
	if _, err := os.Stat(filepath.Join(s.dir, "hosts.yaml.bak")); err == nil {
		t.Error("a refused request wrote a backup, so it had started writing")
	}
}

// The list is the whole authorized scope. It must not be possible to widen it
// with a range, a mask, a wildcard, or two names at once.
func TestAddComputerChecksTheName(t *testing.T) {
	s, path := manageServer(t, commentedList)

	refused := []string{
		"", " ", "WS03 WS04", "10.0.0.0/24", "10.0.0.1-50", "192.168.1.*", "WS0?",
		`\\WS03`, "../WS03", "WS03:445", "WS_03", strings.Repeat("a", 254),
	}
	for _, name := range refused {
		t.Run("refuses "+name, func(t *testing.T) {
			rec := postTo(t, s, addHostPath, url.Values{
				"name": {name}, "confirm": {"1"}, "csrf": {s.csrf},
			}, nil)
			if rec.Code != http.StatusForbidden {
				t.Errorf("adding %q = %d, want 403", name, rec.Code)
			}
		})
	}
	h := loadList(t, path)
	if len(h) != 1 {
		t.Fatalf("the list holds %d computers, want the 1 it started with", len(h))
	}

	// One real computer name is accepted, and recorded with who added it.
	rec := postTo(t, s, addHostPath, url.Values{
		"name": {"ws03.lab.example.test"}, "label": {"finance laptop"},
		"confirm": {"1"}, "csrf": {s.csrf},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("adding a real name = %d, want 303: %s", rec.Code, rec.Body.String())
	}
	h = loadList(t, path)
	if len(h) != 2 {
		t.Fatalf("the list holds %d computers, want 2", len(h))
	}
	added := h[1]
	if added.Name != "ws03.lab.example.test" || added.Label != "finance laptop" {
		t.Errorf("added %+v", added)
	}
	if added.AddedBy == "" || added.Added == "" {
		t.Errorf("the entry does not record who added it and when: %+v", added)
	}
}

// Adding a computer is granting permission to read it, so the person has to say
// it is inside the scope somebody signed for.
func TestAddComputerNeedsTheScopeConfirmed(t *testing.T) {
	s, path := manageServer(t, commentedList)
	rec := postTo(t, s, addHostPath, url.Values{"name": {"WS03"}, "csrf": {s.csrf}}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("adding without the confirmation = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "approved scope") {
		t.Errorf("the refusal should say what is missing, got %q", rec.Body.String())
	}
	if len(loadList(t, path)) != 1 {
		t.Error("the computer was added anyway")
	}
}

// An approval with a date on it is only an approval while the date holds, and
// that governs changing the list as much as scanning.
func TestHostChangesRefusedWhenTheApprovalIsNotInForce(t *testing.T) {
	tests := map[string]string{
		"expired":         strings.Replace(commentedList, `expires: "2026-12-31"`, `expires: "2026-10-01"`, 1),
		"approver TODO":   strings.Replace(commentedList, `approved_by: "J. Lee, IT Manager"`, `approved_by: "TODO"`, 1),
		"scope TODO":      strings.Replace(commentedList, `scope: "quarterly CIS review of the lab"`, `scope: "TODO"`, 1),
		"nobody approved": strings.Replace(commentedList, `approved_by: "J. Lee, IT Manager"`, `approved_by: ""`, 1),
	}
	for name, list := range tests {
		t.Run(name, func(t *testing.T) {
			s, path := manageServer(t, list)
			before := readFile(t, path)

			for _, target := range []string{addHostPath, skipHostPath, removeHostPath, testHostPath} {
				rec := postTo(t, s, target, url.Values{
					"name": {"SQL-02"}, "confirm": {"1"}, "csrf": {s.csrf},
				}, nil)
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s = %d, want 403", target, rec.Code)
				}
			}
			if readFile(t, path) != before {
				t.Error("the host list was changed without an approval in force")
			}
			// And the page says so instead of offering the buttons.
			body := get(t, s, "/scan").Body.String()
			if !strings.Contains(body, "The host list cannot be changed") {
				t.Error("the Manage computers card should say the list is locked")
			}
			if strings.Contains(body, `action="/hosts/add"`) {
				t.Error("the add form should not be offered while the list is locked")
			}
		})
	}
}

// The comments in the file are where the reasons live, and a change from the
// dashboard has to leave them alone.
func TestAddingThroughThePageKeepsTheFilesComments(t *testing.T) {
	s, path := manageServer(t, commentedList)

	rec := postTo(t, s, addHostPath, url.Values{
		"name": {"WS03"}, "label": {"finance laptop"}, "confirm": {"1"}, "csrf": {s.csrf},
	}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add = %d, want 303: %s", rec.Code, rec.Body.String())
	}

	after := readFile(t, path)
	for _, comment := range []string{
		"# The computers we are approved to read.",
		"# Moved to the new rack in September.",
	} {
		if !strings.Contains(after, comment) {
			t.Errorf("the edit lost the comment %q:\n%s", comment, after)
		}
	}
	if !strings.Contains(after, "WS03") {
		t.Error("the computer was not added")
	}
	// The file that was there before is kept, and the change is on the record.
	if backup := readFile(t, path+".bak"); backup != commentedList {
		t.Error("the backup is not the file that was there before")
	}
	log := readFile(t, filepath.Join(s.dir, "hosts-changes.log"))
	if !strings.Contains(log, "added WS03") {
		t.Errorf("the change log does not record the addition: %q", log)
	}
}

func TestSkipIncludeAndRemoveThroughThePage(t *testing.T) {
	s, path := manageServer(t, commentedList)

	// Skip, then include again.
	if rec := postTo(t, s, skipHostPath, url.Values{
		"name": {"SQL-02"}, "csrf": {s.csrf},
	}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("skip = %d, want 303", rec.Code)
	}
	if !loadList(t, path)[0].Skip {
		t.Error("SQL-02 should be skipped")
	}
	if rec := postTo(t, s, skipHostPath, url.Values{
		"name": {"SQL-02"}, "include": {"1"}, "csrf": {s.csrf},
	}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("include = %d, want 303", rec.Code)
	}
	if loadList(t, path)[0].Skip {
		t.Error("SQL-02 should be back in scans")
	}

	// Removing a computer withdraws permission to read it, and leaves the
	// evidence already saved for it exactly where it is.
	evidence := filepath.Join(s.dir, "SQL-02")
	if err := os.MkdirAll(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(evidence, "scan-SQL-02.json")
	if err := os.WriteFile(saved, []byte(`{"host":"SQL-02"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := postTo(t, s, removeHostPath, url.Values{
		"name": {"SQL-02"}, "csrf": {s.csrf},
	}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("remove = %d, want 303", rec.Code)
	}
	if len(loadList(t, path)) != 0 {
		t.Error("SQL-02 should be off the list")
	}
	if _, err := os.Stat(saved); err != nil {
		t.Errorf("removing a computer deleted its evidence: %v", err)
	}
}

// The Manage computers card shows the list as the file has it.
func TestManageComputersCard(t *testing.T) {
	s, _ := manageServer(t, commentedList)
	body := get(t, s, "/scan").Body.String()

	for _, want := range []string{
		"Manage computers", "SQL-02", "database server", "Add a computer",
		"quarterly CIS review of the lab", "J. Lee, IT Manager", "2026-12-31",
		"NOT TESTED", `action="/hosts/add"`, `action="/hosts/skip"`, `action="/hosts/remove"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the Manage computers card is missing %q", want)
		}
	}
}

// Without a host list there is nothing to manage, and the page says so rather
// than offering forms that cannot work.
func TestManageComputersWithoutAHostList(t *testing.T) {
	s, _ := testServer(t)
	s.hostsPath = ""
	body := get(t, s, "/scan").Body.String()
	if !strings.Contains(body, "No host list") {
		t.Error("the page should say there is no host list")
	}
	if strings.Contains(body, `action="/hosts/add"`) {
		t.Error("the add form should not be offered with no host list")
	}
	rec := postTo(t, s, addHostPath, url.Values{
		"name": {"WS03"}, "confirm": {"1"}, "csrf": {s.csrf},
	}, nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("adding with no host list = %d, want 403", rec.Code)
	}
}

// ---------- helpers ----------

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func loadList(t *testing.T, path string) []fleet.Host {
	t.Helper()
	h, err := fleet.Load(path)
	if err != nil {
		t.Fatalf("the host list does not load: %v", err)
	}
	return h.Hosts
}
