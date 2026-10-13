//go:build windows

package report

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// fileLock is an exclusive, cross-process lock on the chain's lock file.
type fileLock struct{ f *os.File }

// lockDir blocks until it holds an exclusive lock on the evidence chain in dir.
// LockFileEx contends across both separate processes and separate handles in
// this process, so concurrent saves are fully serialized.
func lockDir(dir string) (*fileLock, error) {
	f, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) unlock() error {
	ol := new(windows.Overlapped)
	err := windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, ol)
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	return err
}
