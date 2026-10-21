package capture

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ttran0012/winbaseline/internal/baseline"
	"github.com/ttran0012/winbaseline/internal/report"
)

// ProposeExceptions returns a draft exceptions list covering every check that
// was drifting when the capture was taken: the YAML a person edits and pastes
// into the baseline themselves. The reason and the approver are left as
// placeholders that baseline validation rejects, so no deviation can be
// approved without someone writing down why it is acceptable and who accepted
// it. The baseline file is never edited here.
func ProposeExceptions(c *Capture, expires time.Time) ([]byte, error) {
	var draft struct {
		Exceptions []baseline.Exception `yaml:"exceptions"`
	}
	for _, id := range c.Drifting() {
		draft.Exceptions = append(draft.Exceptions, baseline.Exception{
			Check:      id,
			Hosts:      []string{c.Host},
			Reason:     baseline.Placeholder,
			ApprovedBy: baseline.Placeholder,
			Expires:    expires.Format(baseline.ExpiryFormat),
		})
	}
	body, err := yaml.Marshal(draft)
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	fmt.Fprintf(&out, "# Draft exceptions for %s, from the capture taken %s.\n#\n",
		c.Host, c.CapturedAt.Format(baseline.ExpiryFormat))
	fmt.Fprintf(&out, "# One entry per check that was drifting at capture time. Replace every %s with\n", baseline.Placeholder)
	out.WriteString("# the reason the deviation is acceptable and the name of the person who accepted\n")
	out.WriteString("# it, delete the entries you are not approving, then paste what is left into the\n")
	out.WriteString("# exceptions list in the baseline file. Nothing here is in force until you do:\n")
	out.WriteString("# this is a draft, the baseline is never edited for you, and a baseline still\n")
	out.WriteString("# holding a placeholder will not load.\n\n")
	out.Write(body)
	return out.Bytes(), nil
}

// SaveProposedExceptions writes the draft beside the capture it came from and
// returns the path. A draft is not evidence of anything, so it is not part of
// the capture chain; like everything else in the results folder, it is never
// overwritten.
func SaveProposedExceptions(dir string, c *Capture, expires time.Time) (string, error) {
	data, err := ProposeExceptions(c, expires)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, report.RecordName("proposed-exceptions", c.Host, c.CapturedAt)+".yaml")
	if err := report.WriteNew(path, data); err != nil {
		return "", err
	}
	return path, nil
}
