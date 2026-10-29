package repo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
		"testdata/demo/go.mod",
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

func TestListLockfilesGitignore(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{
		"go.mod",
		"build/go.mod",           // ignored dir (root .gitignore "build/")
		"dist/a/go.mod",          // ignored dir (root .gitignore "/dist")
		"keep/dist/go.mod",       // "/dist" is anchored to the root, so kept
		"tmp/x/Cargo.lock",       // ignored dir (nested pattern "**/x")
		"tmp/y/Cargo.lock",       // kept
		"py/requirements.txt",    // ignored file (root .gitignore "requirements.txt")
		"app/out/yarn.lock",      // ignored dir (app/.gitignore "out")
		"app/yarn.lock",          // kept
		"other/out/yarn.lock",    // app/.gitignore does not apply outside app/
		"cmt/#go.mod/Cargo.lock", // comment lines are not patterns
	} {
		write(t, root, f)
	}
	gitignores := map[string]string{
		".gitignore":     "# build output\nbuild/\n/dist\n\nrequirements.txt\r\n#go.mod\n",
		"tmp/.gitignore": "**/x\n",
		"app/.gitignore": "out\n",
	}
	for rel, body := range gitignores {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ListLockfiles(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"app/yarn.lock",
		"cmt/#go.mod/Cargo.lock",
		"go.mod",
		"keep/dist/go.mod",
		"other/out/yarn.lock",
		"tmp/y/Cargo.lock",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestListLockfilesGitignoreNegation(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{"a/go.mod", "b/go.mod", "c/go.mod"} {
		write(t, root, f)
	}
	// "!b/" re-includes b within the same .gitignore file.
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("*/\n!b/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ListLockfiles(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"b/go.mod"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestListLockfilesMissingRoot(t *testing.T) {
	if _, err := ListLockfiles(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("ListLockfiles on a missing root returned nil error")
	}
}

func TestListLockfilesScannerFiles(t *testing.T) {
	root := t.TempDir()
	for _, f := range []string{
		"app/mix.lock",
		"ios/Podfile.lock",
		"sbom/app.cdx.json",
		"sbom/bom.json",
		"sbom/Upper.SPDX.JSON",
		"android/gradle/verification-metadata.xml",
	} {
		write(t, root, f)
	}
	got, err := ListLockfiles(root)
	if err != nil {
		t.Fatal(err)
	}
	// Podfile.lock is not read by osv-scanner v2.7.0, so it is not listed.
	want := []string{
		"android/gradle/verification-metadata.xml",
		"app/mix.lock",
		"sbom/Upper.SPDX.JSON",
		"sbom/app.cdx.json",
		"sbom/bom.json",
	}
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

// fakeGit puts a git stub that prints stdout and exits with code on PATH.
func fakeGit(t *testing.T, stdout string, code int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake is not supported on windows")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s' '" + stdout + "'\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestDisplayNameSanitizesOrigin(t *testing.T) {
	const osc52 = "https://github.com/jedipunkz/scomp\x1b]52;c;SGVsbG8=\x07.git\n"
	fakeGit(t, osc52, 0)
	if got := DisplayName(context.Background(), "/repo"); got != "github.com/jedipunkz/scomp" {
		t.Errorf("DisplayName = %q, want %q", got, "github.com/jedipunkz/scomp")
	}
}

func TestDisplayNameFallbackSanitizesRoot(t *testing.T) {
	fakeGit(t, "", 1)
	if got := DisplayName(context.Background(), "/repo\x07\x1b]2;pwned\x07"); got != "/repo" {
		t.Errorf("DisplayName = %q", got)
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
