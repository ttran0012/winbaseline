//go:build windows

package main

import (
	"testing"

	"github.com/ttran0012/winbaseline/internal/report"
)

func TestExitCode(t *testing.T) {
	rejected := report.CaptureStatusRejected + "capture chain broken after 1 valid capture(s)"

	tests := []struct {
		name string
		scan report.Scan
		want int
	}{
		{"nothing to report", report.Scan{
			Summary: report.Summary{Total: 35, Compliant: 35}}, 0},
		{"drift", report.Scan{
			Summary: report.Summary{Total: 35, Compliant: 34, Drift: 1}}, 1},
		{"approved exceptions are not drift", report.Scan{
			Summary: report.Summary{Total: 35, Compliant: 32, Exceptions: 3}}, 0},
		{"unreadable checks do not change the exit code", report.Scan{
			Summary: report.Summary{Total: 35, Compliant: 28, Errors: 7}}, 0},
		{"policy clean but something changed", report.Scan{
			Summary: report.Summary{Total: 35, Compliant: 35, Changed: 2}}, 4},
		{"drift outranks a change", report.Scan{
			Summary: report.Summary{Total: 35, Compliant: 33, Drift: 1, Changed: 2}}, 1},

		// A capture that cannot be trusted is reported as an evidence problem,
		// and it outranks the findings: the scan still ran and was saved, but
		// until the capture folder is sorted out nobody can say what changed.
		{"rejected capture", report.Scan{
			CaptureStatus: rejected,
			Summary:       report.Summary{Total: 35, Compliant: 35}}, 3},
		{"rejected capture outranks drift", report.Scan{
			CaptureStatus: rejected,
			Summary:       report.Summary{Total: 35, Compliant: 30, Drift: 5}}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.scan); got != tt.want {
				t.Errorf("exitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}
