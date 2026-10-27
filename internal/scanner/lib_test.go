package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jedipunkz/scomp/internal/model"
)

func TestLibActions(t *testing.T) {
	a := Lib{}.Actions("/r")
	if !reflect.DeepEqual(a.DirectoryPaths, []string{"/r"}) || !a.Recursive {
		t.Errorf("must scan /r recursively: %+v", a)
	}
	if a.CompareOffline || a.DownloadDatabases || a.TransitiveScanning.Disabled {
		t.Errorf("online actions must not set offline flags: %+v", a)
	}
	if !reflect.DeepEqual(a.PluginsEnabled, []string{"lockfile", "sbom", "directory"}) {
		t.Errorf("plugins = %v, want the scan source defaults", a.PluginsEnabled)
	}

	off := Lib{Offline: true}.Actions("/r")
	if !off.CompareOffline || !off.DownloadDatabases || !off.TransitiveScanning.Disabled {
		t.Errorf("offline actions must match Exec offline args: %+v", off)
	}
}

func TestLibNoPackages(t *testing.T) {
	_, err := Lib{}.Scan(context.Background(), t.TempDir())
	if !errors.Is(err, model.ErrNoLockfiles) {
		t.Fatalf("err = %v, want ErrNoLockfiles", err)
	}
}

func TestLibCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Lib{}.Scan(ctx, t.TempDir())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// TestLibMatchesExec checks that both scanners produce identical findings.
// It needs network access and osv-scanner in PATH, so it only runs with
// SCOMP_INTEGRATION=1.
func TestLibMatchesExec(t *testing.T) {
	if os.Getenv("SCOMP_INTEGRATION") != "1" {
		t.Skip("set SCOMP_INTEGRATION=1 to run")
	}
	if _, err := exec.LookPath("osv-scanner"); err != nil {
		t.Skip("osv-scanner not in PATH")
	}
	root := t.TempDir()
	files := map[string]string{
		"go.mod":           "module example.com/sample\n\ngo 1.21\n\nrequire golang.org/x/net v0.17.0\n",
		"requirements.txt": "requests==2.28.0\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, offline := range []bool{false, true} {
		e, err := NewExec(offline)
		if err != nil {
			t.Fatal(err)
		}
		want, err := e.Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("exec (offline=%v): %v", offline, err)
		}
		got, err := Lib{Offline: offline}.Scan(context.Background(), root)
		if err != nil {
			t.Fatalf("lib (offline=%v): %v", offline, err)
		}
		if len(want) == 0 {
			t.Fatalf("offline=%v: exec found nothing; sample is not vulnerable anymore?", offline)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("offline=%v: lib returned %d findings, exec %d; results differ", offline, len(got), len(want))
		}
	}
}
