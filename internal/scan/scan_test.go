package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ttran0012/winbaseline/internal/baseline"
)

// Three minimal but valid baselines, one per role, each with a distinct name so
// a test can tell which one a Selector chose.
const (
	wsBaseline = `name: Workstation
version: 1.0.0
checks:
  - id: REG-001
    title: UAC
    severity: high
    type: registry
    hive: HKLM
    path: A\B
    value: V
    operator: equals
    expected: "1"
`
	msBaseline = `name: Member Server
version: 2.0.0
checks:
  - id: SVC-001
    title: Spooler disabled
    severity: medium
    type: service
    service: Spooler
    expected: disabled_or_absent
exceptions:
  - check: SVC-001
    reason: "this is a print server"
    approved_by: "J. Lee"
    expires: "2099-12-31"
`
	dcBaseline = `name: Domain Controller
version: 3.0.0
checks:
  - id: REG-001
    title: UAC
    severity: high
    type: registry
    hive: HKLM
    path: A\B
    value: V
    operator: equals
    expected: "1"
`
)

// folderWithBaselines writes the three role baselines into a temp folder under
// the names the selector looks for.
func folderWithBaselines(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		BaselineWorkstation:      wsBaseline,
		BaselineMemberServer:     msBaseline,
		BaselineDomainController: dcBaseline,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func role(r int) func() (int, error) { return func() (int, error) { return r, nil } }
func roleFails() func() (int, error) {
	return func() (int, error) { return 0, fmt.Errorf("unreachable") }
}
func roleNever(t *testing.T) func() (int, error) {
	return func() (int, error) { t.Fatal("the role was read when it should not have been"); return 0, nil }
}

func TestBaselineForRole(t *testing.T) {
	want := map[int]string{
		0: BaselineWorkstation, 1: BaselineWorkstation,
		2: BaselineMemberServer, 3: BaselineMemberServer,
		4: BaselineDomainController, 5: BaselineDomainController,
		9: BaselineWorkstation, // anything unexpected is held to the workstation baseline
	}
	for r, file := range want {
		if got := BaselineForRole(r); got != file {
			t.Errorf("BaselineForRole(%d) = %q, want %q", r, got, file)
		}
	}
}

// A computer with no host-list baseline is read against the one its role picks.
func TestSelectorChoosesByRole(t *testing.T) {
	sel := Selector{Folder: folderWithBaselines(t)}
	for r, wantName := range map[int]string{5: "Domain Controller", 3: "Member Server", 1: "Workstation"} {
		b, _, err := sel.resolve("WS01", role(r))
		if err != nil {
			t.Fatalf("role %d: %v", r, err)
		}
		if b.Name != wantName {
			t.Errorf("role %d chose %q, want %q", r, b.Name, wantName)
		}
	}
}

// A baseline named in the host list wins over the role, and the role is not even
// read.
func TestSelectorPerHostFieldWins(t *testing.T) {
	sel := Selector{
		Folder:  folderWithBaselines(t),
		PerHost: map[string]string{"srv01": BaselineMemberServer},
	}
	// The role would say domain controller; the host-list assignment overrides it.
	b, file, err := sel.resolve("SRV01", roleNever(t))
	if err != nil {
		t.Fatal(err)
	}
	if b.Name != "Member Server" || file != BaselineMemberServer {
		t.Errorf("chose %q (%s), want the Member Server baseline", b.Name, file)
	}
}

// A forced baseline (-baseline) wins over everything and reads nothing.
func TestSelectorForcedWins(t *testing.T) {
	forced := &baseline.Baseline{Name: "Forced", Version: "0.0.1"}
	sel := Selector{
		Folder:     folderWithBaselines(t),
		Forced:     forced,
		ForcedName: "forced.yaml",
		PerHost:    map[string]string{"srv01": BaselineMemberServer},
	}
	b, file, err := sel.resolve("SRV01", roleNever(t))
	if err != nil {
		t.Fatal(err)
	}
	if b != forced || file != "forced.yaml" {
		t.Errorf("chose %q (%s), want the forced baseline", b.Name, file)
	}
}

// The exceptions applied to a scan are the ones in the baseline it was read
// against: the member-server baseline excepts SVC-001, the workstation one does
// not, so a scan picks up the right set.
func TestSelectorCarriesTheRightExceptions(t *testing.T) {
	sel := Selector{Folder: folderWithBaselines(t)}

	ms, _, err := sel.resolve("SRV01", role(3))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms.Exceptions) != 1 || ms.Exceptions[0].Check != "SVC-001" {
		t.Errorf("member-server baseline exceptions = %+v, want one for SVC-001", ms.Exceptions)
	}

	ws, _, err := sel.resolve("WS01", role(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws.Exceptions) != 0 {
		t.Errorf("workstation baseline exceptions = %+v, want none", ws.Exceptions)
	}
}

// A role that cannot be read (an unreachable computer) falls back to the
// workstation baseline, so the scan still runs and records the attempt.
func TestSelectorFallsBackWhenRoleUnreadable(t *testing.T) {
	sel := Selector{Folder: folderWithBaselines(t)}
	b, file, err := sel.resolve("WS01", roleFails())
	if err != nil {
		t.Fatal(err)
	}
	if file != BaselineWorkstation || b.Name != "Workstation" {
		t.Errorf("fallback chose %q (%s), want the workstation baseline", b.Name, file)
	}
}

func TestSelectorRejectsAnUnknownBaseline(t *testing.T) {
	dir := folderWithBaselines(t)

	// A host-list assignment that names a file that is not there.
	sel := Selector{Folder: dir, PerHost: map[string]string{"srv01": "nope.yaml"}}
	if _, _, err := sel.resolve("SRV01", roleNever(t)); err == nil {
		t.Error("a per-host baseline naming a missing file should be refused")
	}

	// A role whose baseline file is missing from the folder.
	empty := Selector{Folder: t.TempDir()}
	if _, _, err := empty.resolve("WS01", role(1)); err == nil {
		t.Error("a role whose baseline file is absent should be refused")
	}

	// An assignment that tries to climb out of the baseline folder.
	bad := Selector{Folder: dir, PerHost: map[string]string{"srv01": "../secret.yaml"}}
	if _, _, err := bad.resolve("SRV01", roleNever(t)); err == nil ||
		!strings.Contains(err.Error(), "plain file name") {
		t.Errorf("a path-traversing baseline name should be refused, got %v", err)
	}
}
