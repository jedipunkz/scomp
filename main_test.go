package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
