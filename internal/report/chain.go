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

func readChain(dir string) ([]ChainEntry, error) {
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
	entries, err := readChain(dir)
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

// Verify checks every scan in the chain. It returns the number of scans that
// verified and an error describing the first problem found.
func Verify(dir string) (int, error) {
	entries, err := readChain(dir)
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
			return i, fmt.Errorf("scan %d (%s) is missing: %w", i+1, e.File, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != e.Hash {
			return i, fmt.Errorf("scan %d (%s) was modified: hash is %s, chain recorded %s", i+1, e.File, got, e.Hash)
		}
		if e.PreviousHash != prev {
			return i, fmt.Errorf("scan %d (%s) is out of order or a scan was removed before it", i+1, e.File)
		}
		var s struct {
			PreviousHash string `json:"previous_hash"`
		}
		if err := json.Unmarshal(data, &s); err != nil || s.PreviousHash != prev {
			return i, fmt.Errorf("scan %d (%s) does not link to the previous scan", i+1, e.File)
		}
		prev = e.Hash
	}
	return len(entries), nil
}
