package serve

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/scan"
)

// One baseline no longer fits a whole fleet: a domain controller and a
// workstation answer to different policies. The dashboard therefore reads a
// folder of baselines rather than a single file, scans each computer against
// the one its role (or the host list) chooses, and shows which computer uses
// which on the Baseline page.

// loadedBaseline is one baseline file in the folder, carrying whatever went
// wrong loading it so the Baseline page can show a broken file rather than
// quietly drop it.
type loadedBaseline struct {
	File     string
	Baseline *baseline.Baseline
	Err      string
}

// selector builds the baseline chooser the dashboard scans with: the folder of
// baselines, the forced file when -baseline was given, and the host list's
// per-computer assignments.
func (s *Server) selector() (scan.Selector, error) {
	sel := scan.Selector{Folder: s.baselineDir}
	if s.baselineFile != "" {
		b, err := baseline.Load(s.baselineFile)
		if err != nil {
			return scan.Selector{}, fmt.Errorf("the forced baseline would not load: %w", err)
		}
		sel.Forced, sel.ForcedName = b, filepath.Base(s.baselineFile)
	}
	if h, err := s.hosts(); err == nil {
		sel.PerHost = h.Baselines()
	}
	return sel, nil
}

// baselines loads every baseline in play, by name. A forced baseline is the
// only one, since it governs every computer; otherwise it is every YAML file in
// the folder.
func (s *Server) baselines() []loadedBaseline {
	if s.baselineFile != "" {
		return []loadedBaseline{loadOne(s.baselineFile, filepath.Base(s.baselineFile))}
	}
	entries, err := os.ReadDir(s.baselineDir)
	if err != nil {
		return nil
	}
	var out []loadedBaseline
	for _, e := range entries {
		if e.IsDir() || !isYAML(e.Name()) {
			continue
		}
		out = append(out, loadOne(filepath.Join(s.baselineDir, e.Name()), e.Name()))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

func loadOne(path, name string) loadedBaseline {
	lb := loadedBaseline{File: name}
	if b, err := baseline.Load(path); err != nil {
		lb.Err = err.Error()
	} else {
		lb.Baseline = b
	}
	return lb
}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

// checkTypesAll merges the check ID → type map across every baseline in the
// folder, so the results page can group a scan's checks whichever baseline it
// used. Check IDs follow one scheme across the baselines, so the merge is
// unambiguous.
func (s *Server) checkTypesAll() map[string]string {
	types := map[string]string{}
	for _, lb := range s.baselines() {
		if lb.Baseline == nil {
			continue
		}
		for _, c := range lb.Baseline.Checks {
			types[c.ID] = c.Type
		}
	}
	return types
}

// allExceptions gathers the approved exceptions from every baseline, so the
// fleet and computer pages can warn about any that are lapsing wherever they
// live.
func (s *Server) allExceptions() []baseline.Exception {
	var out []baseline.Exception
	for _, lb := range s.baselines() {
		if lb.Baseline != nil {
			out = append(out, lb.Baseline.Exceptions...)
		}
	}
	return out
}
