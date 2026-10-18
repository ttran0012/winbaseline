package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ttran0012/winbaseline/internal/compare"
)

func TestSummarize(t *testing.T) {
	tests := []struct {
		name    string
		results []compare.Result
		want    Summary
	}{
		{"no results", nil, Summary{}},
		{"one of each status", []compare.Result{
			{Status: compare.Compliant},
			{Status: compare.Drift},
			{Status: compare.Exception},
			{Status: compare.Error},
		}, Summary{Total: 4, Compliant: 1, Drift: 1, Exceptions: 1, Errors: 1}},
		// driftscan exits 1 on Summary.Drift, so an approved exception must not
		// be counted there.
		{"exceptions are counted apart from drift", []compare.Result{
			{Status: compare.Exception},
			{Status: compare.Exception},
			{Status: compare.Compliant},
		}, Summary{Total: 3, Compliant: 1, Exceptions: 2}},
		{"an unrecognized status counts as an error", []compare.Result{
			{Status: "SOMETHING ELSE"},
		}, Summary{Total: 1, Errors: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Summarize(tt.results); got != tt.want {
				t.Errorf("Summarize() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPrintShowsExceptionCount(t *testing.T) {
	results := []compare.Result{
		{ID: "SVC-001", Status: compare.Exception, Severity: "medium", Note: "approved exception: vendor app"},
		{ID: "SVC-002", Status: compare.Drift, Severity: "high"},
	}
	var out strings.Builder
	Print(&out, Scan{Results: results, Summary: Summarize(results)})
	for _, want := range []string{"1 drift", "1 approved exception", "SVC-001  EXCEPTION"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output does not contain %q:\n%s", want, out.String())
		}
	}
}

func TestSummarizeCountsChanges(t *testing.T) {
	tests := []struct {
		name    string
		results []compare.Result
		want    Summary
	}{
		{"changes are counted across statuses", []compare.Result{
			{Status: compare.Compliant, Change: compare.Changed},
			{Status: compare.Drift, Change: compare.Changed},
			{Status: compare.Compliant, Change: compare.Unchanged},
			{Status: compare.Compliant, Change: compare.NewCheck},
		}, Summary{Total: 4, Compliant: 3, Drift: 1, Changed: 2}},
		{"a scan with no capture counts no changes", []compare.Result{
			{Status: compare.Compliant},
			{Status: compare.Drift},
		}, Summary{Total: 2, Compliant: 1, Drift: 1}},
		{"unchanged and new checks are not changes", []compare.Result{
			{Status: compare.Compliant, Change: compare.Unchanged},
			{Status: compare.Compliant, Change: compare.NewCheck},
		}, Summary{Total: 2, Compliant: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Summarize(tt.results); got != tt.want {
				t.Errorf("Summarize() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPrintShowsChangesWhenComparedWithACapture(t *testing.T) {
	results := []compare.Result{
		{ID: "SVC-001", Status: compare.Drift, Severity: "high", Change: compare.Changed},
		{ID: "SVC-002", Status: compare.Compliant, Severity: "low", Change: compare.Unchanged},
		{ID: "SVC-003", Status: compare.Compliant, Severity: "low", Change: compare.NewCheck},
	}
	s := Scan{
		Results: results,
		Summary: Summarize(results),
		Capture: &CaptureRef{
			File:       "capture-LAB-WIN11-20261001-080000-000.json",
			Hash:       "abc123",
			CapturedAt: time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC),
		},
	}
	var out strings.Builder
	Print(&out, s)
	page := out.String()

	for _, want := range []string{
		"CHANGE",
		"CHANGED",
		"UNCHANGED",
		"NEW_CHECK",
		"1 changed since capture 2026-10-01",
		"Compared with capture: capture-LAB-WIN11-20261001-080000-000.json",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("console output is missing %q:\n%s", want, page)
		}
	}
}

// A computer with no capture has nothing to say about change, so its output
// stays exactly as it was before captures existed.
func TestPrintWithoutACaptureHasNoChangeColumn(t *testing.T) {
	results := []compare.Result{{ID: "SVC-001", Status: compare.Drift, Severity: "high"}}
	var out strings.Builder
	Print(&out, Scan{Results: results, Summary: Summarize(results)})
	page := out.String()

	if strings.Contains(page, "CHANGE") {
		t.Errorf("a scan with no capture should not print a change column:\n%s", page)
	}
	if strings.Contains(page, "since capture") {
		t.Errorf("a scan with no capture should not mention one:\n%s", page)
	}
	if !strings.Contains(page, "1 drift") {
		t.Errorf("the usual summary is missing:\n%s", page)
	}
}

// A capture that could not be trusted has to be impossible to miss on the
// console, and it must not look like a scan that simply has no capture.
func TestPrintWarnsWhenTheCaptureWasRejected(t *testing.T) {
	results := []compare.Result{{ID: "SVC-001", Status: compare.Drift, Severity: "high"}}
	s := Scan{
		Results:       results,
		Summary:       Summarize(results),
		CaptureStatus: CaptureStatusRejected + "capture capture-LAB-WIN11-20261001-080000-000.json was modified after it was recorded",
	}
	var out strings.Builder
	Print(&out, s)
	page := out.String()

	for _, want := range []string{
		"WARNING: this scan was NOT compared with an approved capture",
		"was modified after it was recorded",
		"driftscan -verify",
		"1 drift", // the policy results are still reported in full
	} {
		if !strings.Contains(page, want) {
			t.Errorf("console output is missing %q:\n%s", want, page)
		}
	}
	// There is no capture to compare against, so there is no change to show.
	if strings.Contains(page, "CHANGE") || strings.Contains(page, "since capture") {
		t.Errorf("a rejected capture should not produce change output:\n%s", page)
	}
}

// The scan is still saved, and the evidence records why no change was reported.
func TestSaveRecordsWhyTheCaptureWasRejected(t *testing.T) {
	dir := t.TempDir()
	results := []compare.Result{{ID: "SVC-001", Status: compare.Drift, Severity: "high"}}
	s := Scan{
		Host:          "LAB-WIN11",
		StartedAt:     time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC),
		Results:       results,
		Summary:       Summarize(results),
		CaptureStatus: CaptureStatusRejected + "record 2 (capture-LAB-WIN11.json) was modified",
	}
	entry, err := Save(dir, s)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, entry.File))
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		CaptureStatus string           `json:"capture_status"`
		Capture       *CaptureRef      `json:"capture"`
		Results       []compare.Result `json:"results"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.CaptureStatus != s.CaptureStatus {
		t.Errorf("capture_status = %q, want %q", saved.CaptureStatus, s.CaptureStatus)
	}
	if saved.Capture != nil {
		t.Errorf("a rejected capture should not be recorded as compared with: %+v", saved.Capture)
	}
	if len(saved.Results) != 1 || saved.Results[0].Change != "" {
		t.Errorf("results = %+v, want the policy result with no change", saved.Results)
	}
	if n, err := Verify(dir); err != nil || n != 1 {
		t.Fatalf("the scan chain should still verify, got %d, %v", n, err)
	}
}

// A healthy scan says nothing about capture status, so existing evidence files
// keep the shape they had.
func TestSaveOmitsCaptureStatusWhenNothingIsWrong(t *testing.T) {
	dir := t.TempDir()
	entry, err := Save(dir, Scan{Host: "LAB-WIN11", StartedAt: time.Date(2026, 10, 18, 9, 30, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, entry.File))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "capture_status") {
		t.Errorf("a healthy scan should not carry a capture_status field:\n%s", data)
	}
}
