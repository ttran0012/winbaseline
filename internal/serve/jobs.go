package serve

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ttran0012/winbaseline/internal/report"
	"github.com/ttran0012/winbaseline/internal/scan"
)

// Starting a scan is the one thing the dashboard does that is not reading, so
// it is the one thing with rules of its own: only one scan runs at a time, only
// computers the host list approves can be named, and the request has to come
// from a form this server rendered. Everything a scan produces still goes
// through the same evidence chain as a scan started from the command line.

// errScanRunning is returned when a scan is asked for while one is running.
// Refusing is better than queueing: a page that is reloaded twice should not
// read every server in the building twice.
var errScanRunning = errors.New("a scan is already running")

// jobResult is what came of reading one computer.
type jobResult struct {
	Host     string
	Summary  report.Summary
	Code     int
	File     string // the evidence that was saved
	Err      string // set when the scan could not be saved
	Captured bool   // the scan was compared with an approved capture
	Note     string // why a computer answered nothing, when it did not
}

// job is one run of the scanner, started from the dashboard.
type job struct {
	ID         string
	StartedAt  time.Time
	FinishedAt time.Time
	Targets    []string
	Current    string // the computer being read right now
	Results    []jobResult
	Done       bool
	Err        string // set when the job could not start or finish
}

// Progress is how far along the job is, for the page to show.
func (j *job) Progress() string {
	return fmt.Sprintf("%d of %d", len(j.Results), len(j.Targets))
}

// Worst is the loudest outcome of the computers read so far, the same scale the
// command line exits with.
func (j *job) Worst() int {
	worst := 0
	for _, r := range j.Results {
		if r.Code > worst {
			worst = r.Code
		}
	}
	return worst
}

// runner holds the one scan that may be running, and the last one that
// finished. Everything the running job writes goes through the mutex, because
// a page is usually being rendered from it at the same time.
type runner struct {
	mu      sync.Mutex
	current *job
	last    *job
	nextID  int
}

// start begins a job, unless one is already running. work runs on its own
// goroutine and reports each computer through the returned recorder.
func (r *runner) start(targets []string, at time.Time, work func(rec *recorder)) (*job, error) {
	r.mu.Lock()
	if r.current != nil {
		r.mu.Unlock()
		return nil, errScanRunning
	}
	r.nextID++
	j := &job{
		ID:        fmt.Sprintf("%s-%d", at.Format("20060102-150405"), r.nextID),
		StartedAt: at,
		Targets:   append([]string(nil), targets...),
	}
	r.current = j
	r.mu.Unlock()

	go func() {
		rec := &recorder{runner: r, job: j}
		defer func() {
			// A panic while reading one computer must not take the dashboard
			// with it, and must not leave the runner looking busy forever.
			if p := recover(); p != nil {
				rec.fail(fmt.Sprintf("the scan stopped unexpectedly: %v", p))
			}
			r.finish(j)
		}()
		work(rec)
	}()
	started, _ := r.state()
	return started, nil
}

// finish moves the running job into the last-finished slot.
func (r *runner) finish(j *job) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j.Done = true
	j.FinishedAt = time.Now()
	j.Current = ""
	r.current, r.last = nil, j
}

// state returns a copy of the running job, or the last one that finished, and
// whether a scan is running now.
func (r *runner) state() (*job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current != nil {
		return copyJob(r.current), true
	}
	if r.last != nil {
		return copyJob(r.last), false
	}
	return nil, false
}

// running reports whether a scan is in progress.
func (r *runner) running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current != nil
}

func copyJob(j *job) *job {
	out := *j
	out.Targets = append([]string(nil), j.Targets...)
	out.Results = append([]jobResult(nil), j.Results...)
	return &out
}

// recorder is how the scanning goroutine reports progress.
type recorder struct {
	runner *runner
	job    *job
}

// reading records which computer is being read now.
func (rec *recorder) reading(host string) {
	rec.runner.mu.Lock()
	defer rec.runner.mu.Unlock()
	rec.job.Current = host
}

// done records the outcome of one computer.
func (rec *recorder) done(res jobResult) {
	rec.runner.mu.Lock()
	defer rec.runner.mu.Unlock()
	rec.job.Current = ""
	rec.job.Results = append(rec.job.Results, res)
}

// fail records that the job itself could not be carried out.
func (rec *recorder) fail(reason string) {
	rec.runner.mu.Lock()
	defer rec.runner.mu.Unlock()
	rec.job.Err = reason
}

// resultOf turns a finished scan into the row the job page shows.
func resultOf(host string, s report.Scan, saved scan.Saved, err error) jobResult {
	res := jobResult{
		Host:     host,
		Summary:  s.Summary,
		Code:     scan.ExitCode(s),
		Captured: s.Capture != nil,
	}
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.File = saved.Entry.File
	if s.Summary.Total > 0 && s.Summary.Errors == s.Summary.Total {
		res.Note = firstError(s)
	}
	if s.CaptureStatus != "" {
		res.Note = s.CaptureStatus
	}
	return res
}

// firstError is the first reason a check could not be read, for the summary of
// a computer that answered nothing.
func firstError(s report.Scan) string {
	for _, res := range s.Results {
		if res.Note != "" {
			return res.Note
		}
	}
	return "no reason recorded"
}
