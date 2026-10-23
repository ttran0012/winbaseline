package serve

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/ttran0012/winbaseline/internal/capture"
	"github.com/ttran0012/winbaseline/internal/collect"
	"github.com/ttran0012/winbaseline/internal/compare"
	"github.com/ttran0012/winbaseline/internal/report"
)

// Approving a scan as the baseline is a write - it records a capture the next
// scan will be measured against - so it is gated exactly like starting a scan:
// a POST carrying this server's form token. What it approves is a scan the
// person has read, not a fresh reading, so it reads no computer. It refuses a
// scan whose evidence does not verify, an approval with no note or no
// confirmation, and a scan with unreadable checks unless those are explicitly
// left out.

// noteMax is the longest an approval note may be. Long enough for why, short
// enough that the field is a note and not a report.
const noteMax = 200

// approve serves the review page on GET and performs the approval on POST.
func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.doApprove(w, r)
		return
	}
	s.reviewPage(w, r)
}

// reviewPage shows what is about to be approved: the scan, its counts, the
// checks that are drifting, and the checks that could not be read and would be
// left out.
func (s *Server) reviewPage(w http.ResponseWriter, r *http.Request) {
	src, saved, ok := s.openScan(w, r)
	if !ok {
		return
	}

	var drifting, unreadable []compare.Result
	for _, res := range report.SortForReport(saved.Scan.Results) {
		switch res.Status {
		case compare.Drift:
			drifting = append(drifting, res)
		case compare.Error:
			unreadable = append(unreadable, res)
		}
	}

	s.render(w, "review.html", struct {
		chrome
		Saved      *savedScan
		Drifting   []compare.Result
		Unreadable []compare.Result
		NoteMax    int
		ScannedAs  string
		Verified   bool
	}{
		chrome:     s.page("Approve as baseline", "fleet", src.Key),
		Saved:      saved,
		Drifting:   drifting,
		Unreadable: unreadable,
		NoteMax:    noteMax,
		ScannedAs:  collect.CurrentUser(),
		Verified:   saved.Verified && s.scanChainVerifies(src),
	})
}

// doApprove records the approval, after checking everything that would make it
// meaningless or unsafe. The order matters: the form has to be trusted before
// its values are read, and the evidence has to verify before it is approved.
func (s *Server) doApprove(w http.ResponseWriter, r *http.Request) {
	if err := s.checkTrustedForm(r); err != nil {
		http.Error(w, "refusing to approve: "+err.Error(), http.StatusForbidden)
		return
	}
	src, saved, ok := s.openScan(w, r)
	if !ok {
		return
	}

	// Approve only evidence that holds up: the whole scan chain for this
	// computer, and this file against the hash the ledger recorded for it.
	if !saved.Verified || !s.scanChainVerifies(src) {
		http.Error(w, "refusing to approve: this scan's evidence does not verify; run Verify evidence "+
			"and resolve the break before approving a baseline", http.StatusForbidden)
		return
	}
	if saved.Scan.CaptureStatus != "" {
		http.Error(w, "refusing to approve: this scan itself reports that its capture could not be "+
			"trusted, so it is not a sound basis for a new one", http.StatusForbidden)
		return
	}

	note := strings.TrimSpace(r.PostFormValue("note"))
	switch {
	case note == "":
		http.Error(w, "refusing to approve: a note saying what you reviewed is required", http.StatusForbidden)
		return
	case len(note) > noteMax:
		http.Error(w, "refusing to approve: the note is longer than the allowed limit", http.StatusForbidden)
		return
	case r.PostFormValue("reviewed") == "":
		http.Error(w, "refusing to approve: tick the box to confirm you reviewed these results", http.StatusForbidden)
		return
	}

	c, err := capture.FromScan(saved.Scan, capture.ApproveOptions{
		ApprovedBy:    collect.CurrentUser(),
		At:            s.now(),
		Note:          note,
		SourceFile:    saved.Entry.File,
		SourceHash:    saved.Entry.Hash,
		ExcludeErrors: r.PostFormValue("exclude_errors") != "",
	})
	if err != nil {
		// The one expected refusal here is unreadable checks left unconfirmed;
		// FromScan's message names them.
		http.Error(w, "refusing to approve: "+err.Error(), http.StatusForbidden)
		return
	}

	capDir := captureFolder(src.Dir)
	if _, err := capture.Save(capDir, c); err != nil {
		http.Error(w, "could not save the approval: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if r.PostFormValue("draft_exceptions") != "" && len(c.Drifting()) > 0 {
		// Best effort: the baseline is a signed record whether or not a draft
		// of suggested exceptions was written beside it.
		_, _ = capture.SaveProposedExceptions(capDir, c, s.now().AddDate(0, 0, capture.ProposedExceptionDays))
	}

	http.Redirect(w, r, "/computer?host="+url.QueryEscape(src.Key), http.StatusSeeOther)
}

// openScan resolves the host and file to a saved scan the ledger lists. They
// are read with FormValue so this works for the GET review page (query string)
// and the POST that approves (form body) alike. A file the ledger does not name
// is a 404, the same as anywhere else.
func (s *Server) openScan(w http.ResponseWriter, r *http.Request) (source, *savedScan, bool) {
	src, err := s.source(r.FormValue("host"))
	if err != nil {
		http.Error(w, "no evidence folder for that computer", http.StatusNotFound)
		return source{}, nil, false
	}
	ix, err := readIndex(src.Dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return source{}, nil, false
	}
	saved, err := ix.load(r.FormValue("file"))
	if errors.Is(err, errUnknownScan) {
		http.Error(w, "no such scan in this results folder", http.StatusNotFound)
		return source{}, nil, false
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return source{}, nil, false
	}
	if saved.Err != "" {
		http.Error(w, "this scan cannot be read: "+saved.Err, http.StatusInternalServerError)
		return source{}, nil, false
	}
	return src, saved, true
}

// scanChainVerifies reports whether the scan ledger for one computer verifies
// end to end, so an approval is only ever built on evidence that holds up.
func (s *Server) scanChainVerifies(src source) bool {
	_, err := report.Verify(src.Dir)
	return err == nil
}
