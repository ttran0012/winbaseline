package report

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The evidence chain links every saved scan to the one before it. Each scan
// file stores the SHA-256 hash of the previous scan file, and chain.log lists
// every file with its own hash. Editing, deleting, or reordering any saved scan
// breaks the chain, and Verify reports where.

// ChainLog is the ledger file name inside the results folder.
const ChainLog = "chain.log"

// lockFile serializes concurrent saves so overlapping scans cannot read the
// same previous hash and fork the chain. It is never part of the chain itself.
const lockFile = "chain.lock"

// GenesisHash is the "previous hash" of the first scan in a chain.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ChainEntry is one line of chain.log.
type ChainEntry struct {
	File         string
	Hash         string
	PreviousHash string
}

// ChainRecord is a record that can be linked into an evidence chain. Verify
// reads previous_hash back out of the saved JSON, so every chained record has
// to store the hash SaveChained gives it.
type ChainRecord interface {
	LinkPrevious(hash string)
}

// ReadChain returns every entry in a folder's ledger, oldest first. A folder
// with no ledger yet simply has no entries, which is not an error.
func ReadChain(dir string) ([]ChainEntry, error) {
	f, err := os.Open(filepath.Join(dir, ChainLog))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []ChainEntry
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s line %d is malformed", ChainLog, line)
		}
		entries = append(entries, ChainEntry{File: fields[0], Hash: fields[1], PreviousHash: fields[2]})
	}
	return entries, sc.Err()
}

// lastHash returns the hash of the newest scan in the chain, or GenesisHash.
func lastHash(dir string) (string, error) {
	entries, err := ReadChain(dir)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return GenesisHash, nil
	}
	return entries[len(entries)-1].Hash, nil
}

func appendChain(dir string, e ChainEntry) error {
	f, err := os.OpenFile(filepath.Join(dir, ChainLog), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s %s %s\n", e.File, e.Hash, e.PreviousHash); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// RecordName builds the base name of a saved record: what kind of record it is,
// which computer it came from, and a timestamp that sorts chronologically. The
// caller adds the extension.
func RecordName(kind, host string, t time.Time) string {
	stamp := strings.Replace(t.Format("20060102-150405.000"), ".", "-", 1)
	return fmt.Sprintf("%s-%s-%s", kind, host, stamp)
}

// SaveChained writes one record as JSON in dir and links it to the newest
// record already in that folder, returning the ledger entry. Saves are
// serialized and no file is ever overwritten, so every folder with a ChainLog
// is append-only: scans and captures each keep their own.
func SaveChained(dir, name string, record ChainRecord) (ChainEntry, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ChainEntry{}, err
	}
	lock, err := lockDir(dir)
	if err != nil {
		return ChainEntry{}, fmt.Errorf("lock evidence chain: %w", err)
	}
	defer func() { _ = lock.unlock() }()
	prev, err := lastHash(dir)
	if err != nil {
		return ChainEntry{}, fmt.Errorf("read evidence chain: %w", err)
	}
	record.LinkPrevious(prev)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return ChainEntry{}, err
	}
	if err := WriteNew(filepath.Join(dir, name), data); err != nil {
		return ChainEntry{}, err
	}
	sum := sha256.Sum256(data)
	entry := ChainEntry{File: name, Hash: hex.EncodeToString(sum[:]), PreviousHash: prev}
	if err := appendChain(dir, entry); err != nil {
		return ChainEntry{}, fmt.Errorf("update evidence chain: %w", err)
	}
	return entry, nil
}

// WriteNew writes a file that must not already exist, so nothing saved in a
// results folder is ever overwritten.
func WriteNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("refusing to overwrite existing evidence: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Verify checks every record in the chain. It returns the number that verified
// and an error describing the first problem found.
func Verify(dir string) (int, error) {
	entries, err := ReadChain(dir)
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, fmt.Errorf("no %s found in %s", ChainLog, dir)
	}
	prev := GenesisHash
	for i, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.File))
		if err != nil {
			return i, fmt.Errorf("record %d (%s) is missing: %w", i+1, e.File, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != e.Hash {
			return i, fmt.Errorf("record %d (%s) was modified: hash is %s, chain recorded %s", i+1, e.File, got, e.Hash)
		}
		if e.PreviousHash != prev {
			return i, fmt.Errorf("record %d (%s) is out of order, or a record was removed before it", i+1, e.File)
		}
		var s struct {
			PreviousHash string `json:"previous_hash"`
		}
		if err := json.Unmarshal(data, &s); err != nil || s.PreviousHash != prev {
			return i, fmt.Errorf("record %d (%s) does not link to the record before it", i+1, e.File)
		}
		prev = e.Hash
	}
	return len(entries), nil
}
