//go:build windows

package collect

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrAuditNeedsLocalAccess is why audit policy is the one thing an agentless
// scan cannot read. Windows exposes no remote audit policy API: auditpol.exe
// has no computer option, and AuditQuerySystemPolicy answers only for the
// machine it runs on. Reading it on another computer means running something
// there, which this scanner deliberately does not do.
var ErrAuditNeedsLocalAccess = errors.New(
	"audit policy cannot be read remotely: Windows has no remote audit policy API, " +
		"so this check needs driftscan run on the computer itself (for example as a scheduled task)")

// auditSetting returns the inclusion setting ("Success and Failure", "Success",
// "Failure", or "No Auditing") for an audit subcategory GUID. auditpol.exe runs
// once per scan; it needs administrator rights.
func (c *Collector) auditSetting(guid string) Reading {
	if c.host != "" {
		return Reading{Err: ErrAuditNeedsLocalAccess}
	}
	if !c.loaded["audit"] {
		c.audit, c.auditErr = loadAuditPolicy()
		c.loaded["audit"] = true
	}
	if c.auditErr != nil {
		return Reading{Err: c.auditErr}
	}
	v, ok := c.audit[strings.ToUpper(guid)]
	if !ok {
		return Reading{}
	}
	return Reading{Present: true, Text: v}
}

func loadAuditPolicy() (map[string]string, error) {
	exe := filepath.Join(os.Getenv("SystemRoot"), "System32", "auditpol.exe")
	out, err := exec.Command(exe, "/get", "/category:*", "/r").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("auditpol: %s (run as administrator)", msg)
	}
	rows, err := csv.NewReader(bytes.NewReader(bytes.TrimSpace(out))).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse auditpol output: %w", err)
	}
	// columns: Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting
	policy := make(map[string]string)
	for _, row := range rows[1:] {
		if len(row) >= 5 {
			policy[strings.ToUpper(strings.TrimSpace(row[3]))] = strings.TrimSpace(row[4])
		}
	}
	return policy, nil
}
