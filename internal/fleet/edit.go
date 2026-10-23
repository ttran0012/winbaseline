package fleet

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// The host list is a file a person wrote and will read again, so changing it
// from the dashboard has to leave it looking like their file: the comments, the
// order, and the layout all survive, because the comments are where the reasons
// live. Every change keeps a .bak of what was there before and appends a line
// to a log beside it, so a list that grew by itself can still be accounted for.
//
// Nothing here can be done while the authorization is missing, unfinished, or
// out of date. Adding a computer to the list is granting permission to read it,
// and permission comes from the approval, not from the button.

// ChangeLog is the file, beside the host list, that records every change made
// through the dashboard.
const ChangeLog = "hosts-changes.log"

// maxNameLength is the longest a DNS name may be.
const maxNameLength = 253

// CheckName rejects anything that is not a single computer name. The host list
// is the whole authorized scope, so it must not be possible to widen it with a
// range, a mask, a wildcard, or two names at once.
func CheckName(name string) error {
	trimmed := strings.TrimSpace(name)
	switch {
	case trimmed == "":
		return fmt.Errorf("a computer name is needed")
	case trimmed != name:
		return fmt.Errorf("%q has spaces around it", name)
	case len(name) > maxNameLength:
		return fmt.Errorf("that name is longer than a computer name can be")
	case strings.ContainsAny(name, " \t"):
		return fmt.Errorf("%q looks like more than one name; add them one at a time", name)
	case strings.Contains(name, "/") || strings.Contains(name, `\`):
		return fmt.Errorf("%q is a path or an address with a mask, not a computer name", name)
	case strings.ContainsAny(name, "*?"):
		return fmt.Errorf("%q is a pattern; every computer has to be listed by name", name)
	case strings.Contains(name, "-") && strings.Count(name, "-") > 0 && isRange(name):
		return fmt.Errorf("%q looks like a range; every computer has to be listed by name", name)
	case !hostName.MatchString(name):
		return fmt.Errorf("%q is not a computer name: letters, digits, hyphens and dots only", name)
	}
	return nil
}

// isRange spots the "10.0.0.1-50" and "PC01-PC09" shapes, where a hyphen is
// being used to mean "through" rather than as part of one name.
func isRange(name string) bool {
	for _, part := range strings.Split(name, ".") {
		if i := strings.Index(part, "-"); i > 0 && i < len(part)-1 {
			before, after := part[:i], part[i+1:]
			if allDigits(before) && allDigits(after) {
				return true
			}
		}
	}
	return false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// Add puts a computer on the list, recording who added it and when.
func Add(path string, h Host, by string, now time.Time) error {
	if err := CheckName(h.Name); err != nil {
		return err
	}
	if strings.ContainsAny(h.Label, "\r\n") {
		return fmt.Errorf("a label is one line")
	}
	return edit(path, by, now, func(hosts *yaml.Node, list *Hosts) (string, error) {
		for _, existing := range list.Hosts {
			if strings.EqualFold(existing.Name, h.Name) {
				return "", fmt.Errorf("%s is already on the list", existing.Name)
			}
		}
		entry := &yaml.Node{Kind: yaml.MappingNode}
		add := func(key, value string) {
			if value == "" {
				return
			}
			entry.Content = append(entry.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Value: key},
				&yaml.Node{Kind: yaml.ScalarNode, Value: value, Style: yaml.DoubleQuotedStyle})
		}
		add("name", h.Name)
		add("label", h.Label)
		add("added", now.Format(DateFormat))
		add("added_by", by)
		// The name reads better unquoted, as the examples in the file have it.
		entry.Content[1].Style = 0
		hosts.Content = append(hosts.Content, entry)
		return fmt.Sprintf("added %s", describe(h)), nil
	})
}

// SetSkip leaves a computer on the list, approved, but out of the next run.
func SetSkip(path, name string, skip bool, by string, now time.Time) error {
	return edit(path, by, now, func(hosts *yaml.Node, list *Hosts) (string, error) {
		entry := findEntry(hosts, name)
		if entry == nil {
			return "", fmt.Errorf("%q is not on the list", name)
		}
		setField(entry, "skip", boolText(skip))
		if skip {
			return fmt.Sprintf("left %s out of scans", name), nil
		}
		return fmt.Sprintf("put %s back into scans", name), nil
	})
}

// Remove takes a computer off the list, which withdraws permission to read it.
// The evidence already saved for it is left exactly where it is: a computer
// leaving the fleet is not a reason to lose the record of what it looked like.
func Remove(path, name string, by string, now time.Time) error {
	return edit(path, by, now, func(hosts *yaml.Node, list *Hosts) (string, error) {
		for i, entry := range hosts.Content {
			if strings.EqualFold(fieldValue(entry, "name"), name) {
				hosts.Content = append(hosts.Content[:i], hosts.Content[i+1:]...)
				return fmt.Sprintf("removed %s (its saved evidence is untouched)", name), nil
			}
		}
		return "", fmt.Errorf("%q is not on the list", name)
	})
}

// edit is the one path through which the file changes: load, check that the
// approval is in force, change the nodes, check the result is still a valid
// list, keep a backup, write, and log.
func edit(path, by string, now time.Time, change func(hosts *yaml.Node, list *Hosts) (string, error)) error {
	original, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read host list: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(original, &doc); err != nil {
		return fmt.Errorf("parse host list: %w", err)
	}

	var list Hosts
	if err := yaml.Unmarshal(original, &list); err != nil {
		return fmt.Errorf("parse host list: %w", err)
	}
	// A list that is not valid now must not be edited into something that looks
	// approved. And an approval that has run out does not authorize a change.
	if err := list.Validate(); err != nil {
		return fmt.Errorf("the host list has to be put right before it can be changed: %w", err)
	}
	if err := list.Authorized(now); err != nil {
		return err
	}

	hosts, err := hostsSequence(&doc)
	if err != nil {
		return err
	}
	summary, err := change(hosts, &list)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("write host list: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("write host list: %w", err)
	}

	// Read back what is about to be written, before anything is replaced.
	var after Hosts
	if err := yaml.Unmarshal(buf.Bytes(), &after); err != nil {
		return fmt.Errorf("the change would leave the host list unreadable: %w", err)
	}
	if err := after.Validate(); err != nil {
		return fmt.Errorf("the change would leave the host list invalid: %w", err)
	}

	if err := os.WriteFile(path+".bak", original, 0o600); err != nil {
		return fmt.Errorf("keep a backup of the host list: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write host list: %w", err)
	}
	return logChange(path, summary, by, now)
}

// hostsSequence finds the hosts: list in the document.
func hostsSequence(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("the host list is empty")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("the host list is not a YAML mapping")
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "hosts" {
			node := root.Content[i+1]
			if node.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("hosts: is not a list")
			}
			return node, nil
		}
	}
	return nil, fmt.Errorf("the host list has no hosts: section")
}

func findEntry(hosts *yaml.Node, name string) *yaml.Node {
	for _, entry := range hosts.Content {
		if strings.EqualFold(fieldValue(entry, "name"), name) {
			return entry
		}
	}
	return nil
}

func fieldValue(entry *yaml.Node, key string) string {
	if entry.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(entry.Content); i += 2 {
		if entry.Content[i].Value == key {
			return entry.Content[i+1].Value
		}
	}
	return ""
}

// setField sets a key on an entry, adding it if it is not there yet.
func setField(entry *yaml.Node, key, value string) {
	for i := 0; i+1 < len(entry.Content); i += 2 {
		if entry.Content[i].Value == key {
			entry.Content[i+1].Value = value
			entry.Content[i+1].Tag = ""
			entry.Content[i+1].Style = 0
			return
		}
	}
	entry.Content = append(entry.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value})
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func describe(h Host) string {
	if h.Label == "" {
		return h.Name
	}
	return fmt.Sprintf("%s (%s)", h.Name, h.Label)
}

// logChange appends one line to the change log beside the host list. A failure
// to log is a failure of the change: a list that grew with no record of who
// added what is the thing this is here to prevent.
func logChange(path, summary, by string, now time.Time) error {
	logPath := filepath.Join(filepath.Dir(path), ChangeLog)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("record the change in %s: %w", ChangeLog, err)
	}
	line := fmt.Sprintf("%s\t%s\t%s\n", now.Format(time.RFC3339), by, summary)
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return fmt.Errorf("record the change in %s: %w", ChangeLog, err)
	}
	return f.Close()
}
