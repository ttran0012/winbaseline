//go:build !windows

package report

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// fileLock is an exclusive, cross-process lock on the chain's lock file.
type fileLock struct{ f *os.File }

// lockDir blocks until it holds an exclusive flock on the evidence chain in dir.
// Each open file description contends, so separate processes and separate
// handles in this process are all serialized.
func lockDir(dir string) (*fileLock, error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) unlock() error {
	err := unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	return err
}
