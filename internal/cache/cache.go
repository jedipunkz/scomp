// Package cache stores scan results keyed by the repository's lockfiles.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jedipunkz/scomp/internal/model"
)

// ErrCorrupt means the cache file could not be decoded. The file has been removed.
var ErrCorrupt = errors.New("cache file is corrupt")

type Entry struct {
	Key       string          `json:"key"`
	Root      string          `json:"root"`
	CreatedAt time.Time       `json:"created_at"`
	Findings  []model.Finding `json:"findings"`
}

// Key returns the SHA-256 of the lockfiles' relative paths and contents.
// files are slash-separated paths relative to root.
func Key(root string, files []string) (string, error) {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s\x00", f)
		fh, err := os.Open(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			return "", err
		}
		n, err := io.Copy(h, fh)
		fh.Close()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "\x00%d\x00", n)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type Store struct {
	Dir string
	Now func() time.Time
}

// DefaultStore uses os.UserCacheDir()/scomp.
func DefaultStore() (*Store, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	return &Store{Dir: filepath.Join(d, "scomp")}, nil
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Path returns the cache file for root.
func (s *Store) Path(root string) string {
	sum := sha256.Sum256([]byte(root))
	return filepath.Join(s.Dir, hex.EncodeToString(sum[:])[:16]+".json")
}

// Load returns the entry for root if it exists, matches key and is younger than ttl.
// A corrupt file is removed and ErrCorrupt is returned.
func (s *Store) Load(root, key string, ttl time.Duration) (Entry, bool, error) {
	p := s.Path(root)
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, err
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		if rmErr := os.Remove(p); rmErr != nil {
			return Entry{}, false, fmt.Errorf("%w (%v); remove failed: %v", ErrCorrupt, err, rmErr)
		}
		return Entry{}, false, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if e.Key != key || e.Root != root || s.now().Sub(e.CreatedAt) > ttl {
		return Entry{}, false, nil
	}
	return e, true, nil
}

// Save atomically writes findings for root.
func (s *Store) Save(root, key string, findings []model.Finding) (Entry, error) {
	if findings == nil {
		findings = []model.Finding{}
	}
	e := Entry{Key: key, Root: root, CreatedAt: s.now(), Findings: findings}
	data, err := json.Marshal(e)
	if err != nil {
		return Entry{}, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return Entry{}, err
	}
	tmp, err := os.CreateTemp(s.Dir, ".tmp-*.json")
	if err != nil {
		return Entry{}, err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return Entry{}, err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return Entry{}, err
	}
	if err := tmp.Close(); err != nil {
		return Entry{}, err
	}
	if err := os.Rename(tmp.Name(), s.Path(root)); err != nil {
		return Entry{}, err
	}
	return e, nil
}
