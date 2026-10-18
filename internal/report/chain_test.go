package report

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func saveScans(t *testing.T, dir string, n int) []string {
	t.Helper()
	var paths []string
	start := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		e, err := Save(dir, Scan{Host: "LAB-WIN11", StartedAt: start.Add(time.Duration(i) * time.Minute), BaselineVersion: "0.2.0"})
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, filepath.Join(dir, e.File))
	}
	return paths
}

func TestChainVerifies(t *testing.T) {
	dir := t.TempDir()
	saveScans(t, dir, 3)
	n, err := Verify(dir)
	if err != nil || n != 3 {
		t.Fatalf("Verify = %d, %v; want 3, nil", n, err)
	}
}

func TestSaveNeverOverwritesEvidence(t *testing.T) {
	dir := t.TempDir()
	s := Scan{Host: "LAB-WIN11", StartedAt: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)}
	if _, err := Save(dir, s); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(dir, s); err == nil { // same host and timestamp
		t.Fatal("second save with the same name should be refused")
	}
	if n, err := Verify(dir); err != nil || n != 1 {
		t.Fatalf("chain should still verify with 1 scan, got %d, %v", n, err)
	}
}

func TestConcurrentSavesKeepChainIntact(t *testing.T) {
	dir := t.TempDir()
	start := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct timestamps so saves differ only by chain position, not file name.
			s := Scan{Host: "LAB-WIN11", StartedAt: start.Add(time.Duration(i) * time.Second)}
			if _, err := Save(dir, s); err != nil {
				t.Errorf("Save: %v", err)
			}
		}(i)
	}
	wg.Wait()
	// Without serialized saves, overlapping runs reuse the same previous hash
	// and Verify fails; the lock makes every scan link to a distinct predecessor.
	if got, err := Verify(dir); err != nil || got != n {
		t.Fatalf("Verify = %d, %v; want %d, nil", got, err, n)
	}
}

func TestChainDetectsEditedScan(t *testing.T) {
	dir := t.TempDir()
	paths := saveScans(t, dir, 3)
	data, _ := os.ReadFile(paths[1])
	edited := strings.Replace(string(data), `"drift": 0`, `"drift": 5`, 1)
	if err := os.WriteFile(paths[1], []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(dir); err == nil || !strings.Contains(err.Error(), "modified") {
		t.Fatalf("expected modification to be detected, got %v", err)
	}
}

func TestChainDetectsDeletedScan(t *testing.T) {
	dir := t.TempDir()
	paths := saveScans(t, dir, 3)
	os.Remove(paths[2])
	if _, err := Verify(dir); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected missing scan to be detected, got %v", err)
	}
}

func TestChainDetectsRemovedLedgerLine(t *testing.T) {
	dir := t.TempDir()
	saveScans(t, dir, 3)
	log := filepath.Join(dir, ChainLog)
	data, _ := os.ReadFile(log)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	os.WriteFile(log, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600) // drop the middle scan from the ledger
	if _, err := Verify(dir); err == nil {
		t.Fatal("expected a removed ledger entry to break the chain")
	}
}
