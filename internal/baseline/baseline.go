// Package baseline loads and validates the YAML baseline definition.
package baseline

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Check types.
const (
	TypeRegistry = "registry"
	TypeService  = "service"
	TypeAccount  = "account"
	TypeGroup    = "group"
	TypeFirewall = "firewall"
	TypeAudit    = "audit"
	TypeSoftware = "software"
)

// Baseline is a versioned set of configuration checks.
type Baseline struct {
	Name      string  `yaml:"name"`
	Version   string  `yaml:"version"`
	Benchmark string  `yaml:"benchmark"`
	Checks    []Check `yaml:"checks"`
}

// Check describes one expected configuration setting.
// Which location fields are used depends on Type.
type Check struct {
	ID       string `yaml:"id"`
	Title    string `yaml:"title"`
	CIS      string `yaml:"cis"`
	Severity string `yaml:"severity"`
	Type     string `yaml:"type"`
	Expected string `yaml:"expected"`

	// registry
	Hive     string  `yaml:"hive"`
	Path     string  `yaml:"path"`
	Value    string  `yaml:"value"`
	Operator string  `yaml:"operator"` // equals | lte | gte
	Default  *uint64 `yaml:"default"`

	// service: short service name; expected disabled | disabled_or_absent
	Service string `yaml:"service"`

	// account: guest | administrator; expected disabled | renamed
	Account string `yaml:"account"`

	// group: administrators; every member must be in Approved
	Group    string   `yaml:"group"`
	Approved []string `yaml:"approved"`

	// firewall: domain | private | public; expected on
	Profile string `yaml:"profile"`

	// audit: subcategory GUID (language independent); expected success | failure | success_and_failure
	Subcategory string `yaml:"subcategory"`

	// software: regular expression matched against installed program names; expected absent
	Pattern string `yaml:"pattern"`
}

// Location describes where the setting lives, for reports.
func (c Check) Location() string {
	switch c.Type {
	case TypeRegistry:
		return fmt.Sprintf(`%s\%s\%s`, c.Hive, c.Path, c.Value)
	case TypeService:
		return "Service: " + c.Service
	case TypeAccount:
		return "Built-in account: " + c.Account
	case TypeGroup:
		return "Local group: " + c.Group
	case TypeFirewall:
		return "Firewall profile: " + c.Profile
	case TypeAudit:
		return "Audit subcategory: " + c.Subcategory
	case TypeSoftware:
		return "Installed software matching: " + c.Pattern
	}
	return c.Type
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
		if err := c.validateType(); err != nil {
			return fmt.Errorf("check %s: %w", c.ID, err)
		}
	}
	return nil
}

func (c Check) validateType() error {
	switch c.Type {
	case TypeRegistry:
		if c.Hive != "HKLM" || c.Path == "" || c.Value == "" {
			return fmt.Errorf("registry checks need hive HKLM, a path, and a value")
		}
		switch c.Operator {
		case "equals", "lte", "gte":
		default:
			return fmt.Errorf("operator must be equals, lte, or gte")
		}
		if _, err := strconv.ParseUint(c.Expected, 10, 64); err != nil {
			return fmt.Errorf("registry expected value must be a whole number")
		}
	case TypeService:
		if c.Service == "" {
			return fmt.Errorf("service checks need a service name")
		}
		return oneOf(c.Expected, "disabled", "disabled_or_absent")
	case TypeAccount:
		if err := oneOf(c.Account, "guest", "administrator"); err != nil {
			return fmt.Errorf("account %w", err)
		}
		return oneOf(c.Expected, "disabled", "renamed")
	case TypeGroup:
		if err := oneOf(c.Group, "administrators"); err != nil {
			return fmt.Errorf("group %w", err)
		}
		if len(c.Approved) == 0 {
			return fmt.Errorf("group checks need an approved member list")
		}
	case TypeFirewall:
		if err := oneOf(c.Profile, "domain", "private", "public"); err != nil {
			return fmt.Errorf("profile %w", err)
		}
		return oneOf(c.Expected, "on")
	case TypeAudit:
		if !guidPattern.MatchString(c.Subcategory) {
			return fmt.Errorf("audit checks need a subcategory GUID like {0CCE9215-69AE-11D9-BED3-505054503030}")
		}
		return oneOf(c.Expected, "success", "failure", "success_and_failure")
	case TypeSoftware:
		if _, err := regexp.Compile(c.Pattern); err != nil || c.Pattern == "" {
			return fmt.Errorf("software checks need a valid pattern")
		}
		return oneOf(c.Expected, "absent")
	default:
		return fmt.Errorf("unsupported type %q", c.Type)
	}
	return nil
}

var guidPattern = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

func oneOf(v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("must be one of: %s (got %q)", strings.Join(allowed, ", "), v)
}
