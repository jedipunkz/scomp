package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jedipunkz/scomp/internal/model"
)

func writeProcVersion(t *testing.T, s string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "version")
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCmdStartCommandRefusesMetacharacters(t *testing.T) {
	for _, u := range []string{
		"https://osv.dev/vulnerability/GHSA-x&calc",
		"https://osv.dev/vulnerability/GHSA-x|calc",
		"https://osv.dev/vulnerability/GHSA-x^calc",
		"https://osv.dev/vulnerability/GHSA-x<calc",
		"https://osv.dev/vulnerability/GHSA-x>calc",
		"https://osv.dev/vulnerability/GHSA-x%PATH%",
		"https://osv.dev/vulnerability/GHSA-x\"calc",
		"https://osv.dev/vulnerability/GHSA-x\x1b]calc",
	} {
		cmd, err := cmdStartCommand(u)
		if err == nil || cmd != nil {
			t.Errorf("cmdStartCommand(%q) = %v, %v; want error and nil cmd", u, cmd, err)
		}
	}
}

func TestCmdStartCommandSafeURL(t *testing.T) {
	const u = "https://osv.dev/vulnerability/GHSA-4v7x-pqxf-cx7m"
	cmd, err := cmdStartCommand(u)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cmd.exe", "/c", "start", "", u}
	if !slices.Equal(cmd.Args, want) {
		t.Errorf("args = %q, want %q", cmd.Args, want)
	}
}

func TestInWSL(t *testing.T) {
	const distro = "WSL_DISTRO_NAME"

	tests := []struct {
		name        string
		getenv      func(string) string
		procVersion string
		want        bool
	}{
		{
			name:        "distro env set",
			getenv:      func(k string) string { return map[string]string{distro: "Ubuntu"}[k] },
			procVersion: writeProcVersion(t, "Linux version 5.15.0"),
			want:        true,
		},
		{
			name:        "wsl2 kernel signature",
			getenv:      func(string) string { return "" },
			procVersion: writeProcVersion(t, "Linux version 5.15.167.4-microsoft-standard-WSL2"),
			want:        true,
		},
		{
			name:        "wsl1 kernel signature",
			getenv:      func(string) string { return "" },
			procVersion: writeProcVersion(t, "Linux version 4.4.0-19041-Microsoft"),
			want:        true,
		},
		{
			name:        "native linux",
			getenv:      func(string) string { return "" },
			procVersion: writeProcVersion(t, "Linux version 6.1.0-gentoo"),
			want:        false,
		},
		{
			name:        "no proc version file",
			getenv:      func(string) string { return "" },
			procVersion: filepath.Join(t.TempDir(), "missing"),
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inWSL(tt.getenv, tt.procVersion); got != tt.want {
				t.Fatalf("inWSL() = %v, want %v", got, tt.want)
			}
		})
	}
}

// runJSONScan runs the json pipeline on dir and returns stdout and stderr.
func runJSONScan(t *testing.T, dir string) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"--json", dir}, &stdout, &stderr); err != nil {
		t.Fatalf("run() error = %v; stderr = %q", err, stderr.String())
	}
	return stdout.String(), stderr.String()
}

func TestRunCacheDisabled(t *testing.T) {
	const warning = "warning: cache disabled:"

	t.Run("DefaultStore error", func(t *testing.T) {
		// os.UserCacheDir fails when HOME and XDG_CACHE_HOME are both empty.
		t.Setenv("HOME", "")
		t.Setenv("XDG_CACHE_HOME", "")
		dir := t.TempDir()

		stdout, stderr := runJSONScan(t, dir)
		if n := strings.Count(stderr, warning); n != 1 {
			t.Fatalf("%q appears %d times, want 1; stderr = %q", warning, n, stderr)
		}
		var findings []model.Finding
		if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
			t.Fatalf("stdout is not JSON: %v; stdout = %q", err, stdout)
		}
	})

	t.Run("cache enabled", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		t.Setenv("XDG_CACHE_HOME", "")
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		_, stderr := runJSONScan(t, dir)
		if strings.Contains(stderr, warning) {
			t.Fatalf("unexpected %q; stderr = %q", warning, stderr)
		}
	})

	t.Run("Key error", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads files regardless of mode")
		}
		t.Setenv("HOME", t.TempDir())
		t.Setenv("XDG_CACHE_HOME", "")
		dir := t.TempDir()
		lock := filepath.Join(dir, "package-lock.json")
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(lock, 0); err != nil {
			t.Fatal(err)
		}

		stdout, stderr := runJSONScan(t, dir)
		if n := strings.Count(stderr, warning); n != 1 {
			t.Fatalf("%q appears %d times, want 1; stderr = %q", warning, n, stderr)
		}
		var findings []model.Finding
		if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
			t.Fatalf("stdout is not JSON: %v; stdout = %q", err, stdout)
		}
	})
}

func TestPrintError_Sanitized(t *testing.T) {
	path := "repo/\x1b]8;;http://evil\x07dir\u202e\x1b[31m"
	err := fmt.Errorf("list lockfiles: %w", &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission})

	var buf bytes.Buffer
	printError(&buf, err)

	got := buf.String()
	for _, bad := range []string{"\x1b", "\x07", "\u202e"} {
		if strings.Contains(got, bad) {
			t.Fatalf("printError() output contains %q: %q", bad, got)
		}
	}
	if want := "scomp: list lockfiles: open repo/dir: permission denied\n"; got != want {
		t.Fatalf("printError() = %q, want %q", got, want)
	}
}
