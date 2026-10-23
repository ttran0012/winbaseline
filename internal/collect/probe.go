//go:build windows

package collect

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// AccessReport is what a read-only probe of a computer found. It answers the
// one question worth asking before a scan is scheduled: can this account read
// this computer at all? The probe opens the two doors a scan uses and closes
// them again. It reads no setting and changes nothing.
type AccessReport struct {
	Host     string
	Registry string // empty when the remote registry answered
	Services string // empty when the service manager answered
	Elapsed  time.Duration
	TimedOut bool
}

// OK reports whether both answered.
func (a AccessReport) OK() bool { return a.Registry == "" && a.Services == "" }

// Summary is one line for the page.
func (a AccessReport) Summary() string {
	switch {
	case a.TimedOut:
		return fmt.Sprintf("no answer within %s", a.Elapsed.Round(time.Millisecond))
	case a.OK():
		return fmt.Sprintf("registry and services answered in %s", a.Elapsed.Round(time.Millisecond))
	case a.Registry != "" && a.Services != "":
		return "neither the registry nor the service manager could be opened"
	case a.Registry != "":
		return "the service manager answered, but the remote registry did not"
	default:
		return "the remote registry answered, but the service manager did not"
	}
}

// AccessTimeout is how long a probe waits. A computer that is switched off
// should be reported in a moment, not after a minute of a blocked call.
const AccessTimeout = 8 * time.Second

// TestAccess probes one computer. The Windows calls it makes cannot be
// cancelled, so a probe that passes its deadline is reported as no answer and
// the call is left to finish on its own; nothing waits for it.
func TestAccess(host string, timeout time.Duration) AccessReport {
	started := time.Now()
	done := make(chan AccessReport, 1)

	go func() {
		var a AccessReport
		if k, err := registry.OpenRemoteKey(host, registry.LOCAL_MACHINE); err != nil {
			a.Registry = err.Error()
		} else {
			k.Close()
		}
		if name, err := windows.UTF16PtrFromString(`\\` + host); err != nil {
			a.Services = err.Error()
		} else if scm, err := windows.OpenSCManager(name, nil, windows.SC_MANAGER_CONNECT); err != nil {
			a.Services = err.Error()
		} else {
			windows.CloseServiceHandle(scm)
		}
		done <- a
	}()

	select {
	case a := <-done:
		a.Host, a.Elapsed = host, time.Since(started)
		return a
	case <-time.After(timeout):
		return AccessReport{
			Host:     host,
			Registry: "no answer in time",
			Services: "no answer in time",
			Elapsed:  time.Since(started),
			TimedOut: true,
		}
	}
}
