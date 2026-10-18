package report

import (
	"strings"
	"testing"

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
