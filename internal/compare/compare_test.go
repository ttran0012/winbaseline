package compare

import (
	"errors"
	"testing"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/collect"
)

func u(v uint64) *uint64 { return &v }

func TestEvaluate(t *testing.T) {
	eq := baseline.Check{ID: "T-1", Operator: "equals", Expected: 1, Hive: "HKLM", Path: `A\B`, Value: "V"}
	lte := baseline.Check{ID: "T-2", Operator: "lte", Expected: 900, Hive: "HKLM", Path: `A\B`, Value: "V"}
	withDefault := eq
	withDefault.Default = u(1)

	tests := []struct {
		name  string
		check baseline.Check
		read  collect.Reading
		want  string
	}{
		{"equal value is compliant", eq, collect.Reading{Present: true, Value: 1}, Compliant},
		{"different value is drift", eq, collect.Reading{Present: true, Value: 0}, Drift},
		{"missing value without default is drift", eq, collect.Reading{}, Drift},
		{"missing value uses secure default", withDefault, collect.Reading{}, Compliant},
		{"lte below limit is compliant", lte, collect.Reading{Present: true, Value: 600}, Compliant},
		{"lte above limit is drift", lte, collect.Reading{Present: true, Value: 1800}, Drift},
		{"read error is reported", eq, collect.Reading{Err: errors.New("access denied")}, Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Evaluate(tt.check, tt.read).Status; got != tt.want {
				t.Errorf("status = %s, want %s", got, tt.want)
			}
		})
	}
}
