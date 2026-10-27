package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"

	"github.com/jedipunkz/scomp/internal/model"
)

// fakeScanner writes a shell script that prints stdout/stderr and exits with code.
func fakeScanner(t *testing.T, stdout, stderr string, code int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake is not supported on windows")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "stdout")
	errf := filepath.Join(dir, "stderr")
	if err := os.WriteFile(out, []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(errf, []byte(stderr), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\ncat '" + out + "'\ncat '" + errf + "' >&2\nexit " + strconv.Itoa(code) + "\n"
	p := filepath.Join(dir, "osv-scanner")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExecScanExitCodes(t *testing.T) {
	sample, err := os.ReadFile("../../testdata/osv-scanner-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		stdout    string
		code      int
		wantCount int
		wantErr   error
		wantExec  bool
	}{
		{name: "no vulnerabilities", stdout: `{"results":[]}`, code: 0, wantCount: 0},
		{name: "vulnerabilities found", stdout: string(sample), code: 1, wantCount: 4},
		{name: "no packages", stdout: "", code: 128, wantErr: model.ErrNoLockfiles},
		{name: "other error", stdout: "", code: 127, wantExec: true},
		{name: "broken json", stdout: "{", code: 1, wantExec: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Exec{Path: fakeScanner(t, tt.stdout, "boom", tt.code)}
			got, err := e.Scan(context.Background(), "/repo")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if tt.wantExec {
				var ee *ExecError
				if !errors.As(err, &ee) {
					t.Fatalf("err = %v, want *ExecError", err)
				}
				if ee.ExitCode != tt.code {
					t.Errorf("exit code = %d, want %d", ee.ExitCode, tt.code)
				}
				if ee.Stderr == "" {
					t.Error("stderr must be kept")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tt.wantCount {
				t.Errorf("got %d findings, want %d", len(got), tt.wantCount)
			}
		})
	}
}

func TestExecArgs(t *testing.T) {
	online := (&Exec{}).Args("/r")
	if want := []string{"scan", "source", "-r", "/r", "--format", "json"}; !slices.Equal(online, want) {
		t.Errorf("online args = %v, want %v", online, want)
	}
	offline := (&Exec{Offline: true}).Args("/r")
	for _, f := range []string{"--offline-vulnerabilities", "--download-offline-databases", "--no-resolve"} {
		if !slices.Contains(offline, f) {
			t.Errorf("offline args %v missing %s", offline, f)
		}
	}
}
