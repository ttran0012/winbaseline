// Package baseline loads and validates the YAML baseline definition.
package baseline

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Baseline is a versioned set of configuration checks.
type Baseline struct {
	Name      string  `yaml:"name"`
	Version   string  `yaml:"version"`
	Benchmark string  `yaml:"benchmark"`
	Checks    []Check `yaml:"checks"`
}

// Check describes one expected configuration setting.
type Check struct {
	ID       string  `yaml:"id"`
	Title    string  `yaml:"title"`
	CIS      string  `yaml:"cis"`
	Severity string  `yaml:"severity"`
	Type     string  `yaml:"type"`
	Hive     string  `yaml:"hive"`
	Path     string  `yaml:"path"`
	Value    string  `yaml:"value"`
	Operator string  `yaml:"operator"`
	Expected uint64  `yaml:"expected"`
	Default  *uint64 `yaml:"default"`
}

// Load reads a baseline file and validates every check.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var b Baseline
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// Validate rejects baselines with missing fields, duplicate IDs, or unknown values.
func (b *Baseline) Validate() error {
	if len(b.Checks) == 0 {
		return fmt.Errorf("baseline %q has no checks", b.Name)
	}
	seen := make(map[string]bool)
	for i, c := range b.Checks {
		if c.ID == "" {
			return fmt.Errorf("check %d: missing id", i+1)
		}
		if seen[c.ID] {
			return fmt.Errorf("check %s: duplicate id", c.ID)
		}
		seen[c.ID] = true
		switch c.Severity {
		case "high", "medium", "low":
		default:
			return fmt.Errorf("check %s: severity must be high, medium, or low", c.ID)
		}
		switch c.Operator {
		case "equals", "lte", "gte":
		default:
			return fmt.Errorf("check %s: operator must be equals, lte, or gte", c.ID)
		}
		if c.Type != "registry" {
			return fmt.Errorf("check %s: unsupported type %q", c.ID, c.Type)
		}
		if c.Hive != "HKLM" || c.Path == "" || c.Value == "" {
			return fmt.Errorf("check %s: registry checks need hive HKLM, a path, and a value", c.ID)
		}
	}
	return nil
}
