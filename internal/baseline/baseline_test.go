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
