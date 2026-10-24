package repo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func write(t *testing.T, root, rel string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(rel), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestListLockfiles(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{
		"go.mod",
		"web/package-lock.json",
		"web/node_modules/x/package-lock.json",
		"vendor/y/go.mod",
		".git/go.mod",
		"py/requirements.txt",
		"README.md",
	} {
		write(t, root, f)
	}
	got, err := ListLockfiles(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"go.mod", "py/requirements.txt", "web/package-lock.json"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFindRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	root, inGit, err := FindRoot(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if inGit {
		t.Skipf("temp dir %s is inside a git repository", dir)
	}
	if root != dir {
		t.Errorf("root = %s, want %s", root, dir)
	}

	if out, err := exec.Command("git", "init", "-q", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	root, inGit, err = FindRoot(context.Background(), sub)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(dir)
	gotEval, _ := filepath.EvalSymlinks(root)
	if !inGit || gotEval != want {
		t.Errorf("root = %s (inGit=%v), want %s", root, inGit, want)
	}
}

func TestRemoteName(t *testing.T) {
	tests := map[string]string{
		"git@github.com:jedipunkz/scomp.git":          "github.com/jedipunkz/scomp",
		"https://github.com/jedipunkz/scomp.git":      "github.com/jedipunkz/scomp",
		"https://user:tok@github.com/jedipunkz/scomp": "github.com/jedipunkz/scomp",
		"ssh://git@gitlab.com:2222/group/sub/proj":    "gitlab.com/group/sub/proj",
		"/local/path/repo":                            "",
		"":                                            "",
	}
	for in, want := range tests {
		if got := remoteName(in); got != want {
			t.Errorf("remoteName(%q) = %q, want %q", in, got, want)
		}
	}
}
