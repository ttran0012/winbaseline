//go:build windows

package collect

import (
	"os"
	"regexp"
	"sort"

	"golang.org/x/sys/windows/registry"
)

var uninstallKeys = []string{
	`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
	`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
}

// softwareMatching lists installed programs whose display name matches pattern.
func (c *Collector) softwareMatching(pattern string) Reading {
	if !c.loaded["software"] {
		c.software, c.softErr = installedSoftware()
		c.loaded["software"] = true
	}
	if c.softErr != nil {
		return Reading{Err: c.softErr}
	}
	re := regexp.MustCompile(pattern) // validated when the baseline loaded
	var matches []string
	for _, name := range c.software {
		if re.MatchString(name) {
			matches = append(matches, name)
		}
	}
	return Reading{Present: len(matches) > 0, List: matches}
}

// installedSoftware returns the display names of programs installed for all users.
func installedSoftware() ([]string, error) {
	seen := map[string]bool{}
	for _, path := range uninstallKeys {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.ENUMERATE_SUB_KEYS)
		if os.IsNotExist(err) {
			continue // the 32-bit key does not exist on every system
		}
		if err != nil {
			return nil, err // e.g. access denied: do not report prohibited software as absent
		}
		subs, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			return nil, err
		}
		for _, s := range subs {
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+s, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			if name, _, err := sk.GetStringValue("DisplayName"); err == nil && name != "" {
				seen[name] = true
			}
			sk.Close()
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
