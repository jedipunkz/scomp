package main

import (
	"os"
	"path/filepath"
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
