package cache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jedipunkz/scomp/internal/model"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestKey(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "go.mod", "module a")
	writeFile(t, root, "web/package-lock.json", "{}")
	files := []string{"go.mod", "web/package-lock.json"}

	k1, err := Key(root, "s", files)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := Key(root, "s", files)
	if k1 != k2 {
		t.Error("key must be deterministic")
	}

	writeFile(t, root, "go.mod", "module b")
	k3, _ := Key(root, "s", files)
	if k3 == k1 {
		t.Error("key must change when content changes")
	}

	k4, _ := Key(root, "s", files[:1])
	if k4 == k3 {
		t.Error("key must change when the file set changes")
	}

	// Moving bytes between path and content must not collide.
	r2 := t.TempDir()
	writeFile(t, r2, "a", "bc")
	writeFile(t, r2, "ab", "c")
	ka, _ := Key(r2, "s", []string{"a"})
	kb, _ := Key(r2, "s", []string{"ab"})
	if ka == kb {
		t.Error("path/content boundary must be unambiguous")
	}

	k5, _ := Key(root, "other", files)
	if k5 == k3 {
		t.Error("key must change when the scanner changes")
	}

	if _, err := Key(root, "s", []string{"missing"}); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestKeyCoversScannerInputs(t *testing.T) {
	root := t.TempDir()
	files := []string{"app/mix.lock", "sbom/app.cdx.json"}
	writeFile(t, root, files[0], "mix")
	writeFile(t, root, files[1], "{}")

	k1, err := Key(root, "s", files)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, root, files[0], "mix changed")
	k2, _ := Key(root, "s", files)
	if k2 == k1 {
		t.Error("key must change when mix.lock changes")
	}
	writeFile(t, root, files[1], `{"bomFormat":"CycloneDX"}`)
	k3, _ := Key(root, "s", files)
	if k3 == k2 {
		t.Error("key must change when a CycloneDX SBOM changes")
	}
}

func TestStoreLoadSave(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &Store{Dir: filepath.Join(t.TempDir(), "scomp"), Now: func() time.Time { return now }}
	findings := []model.Finding{{ID: "GO-1", Severity: model.SeverityHigh, Package: model.Package{Name: "a"}}}

	if _, ok, err := s.Load("/r", "k", time.Hour); ok || err != nil {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	if _, err := s.Save("/r", "k", findings); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 700", perm)
	}
	info, err = os.Stat(s.Path("/r"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 600", perm)
	}

	tests := []struct {
		name   string
		root   string
		key    string
		after  time.Duration
		wantOK bool
	}{
		{"hit", "/r", "k", 0, true},
		{"key mismatch", "/r", "other", 0, false},
		{"other root", "/other", "k", 0, false},
		{"within ttl", "/r", "k", time.Hour, true},
		{"expired", "/r", "k", time.Hour + time.Second, false},
		{"created in the future", "/r", "k", -time.Second, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s.Now = func() time.Time { return now.Add(tt.after) }
			e, ok, err := s.Load(tt.root, tt.key, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && (len(e.Findings) != 1 || e.Findings[0].Severity != model.SeverityHigh || !e.CreatedAt.Equal(now)) {
				t.Errorf("entry = %+v", e)
			}
		})
	}
}

func TestStoreCorrupt(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	p := s.Path("/r")
	if err := os.WriteFile(p, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, ok, err := s.Load("/r", "k", time.Hour)
	if ok || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("ok=%v err=%v, want ErrCorrupt", ok, err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("corrupt file must be removed, stat err = %v", err)
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	if _, err := s.Save("/r", "k", nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(s.Path("/r")) {
		t.Errorf("unexpected files: %v", entries)
	}
	e, ok, err := s.Load("/r", "k", time.Hour)
	if err != nil || !ok || e.Findings == nil {
		t.Errorf("nil findings must round-trip as empty slice: %+v ok=%v err=%v", e, ok, err)
	}
}
