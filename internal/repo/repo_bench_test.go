package repo

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// benchNames are typical source-tree file names, with a few lockfiles.
var benchNames = []string{
	"main.go", "main_test.go", "README.md", "Makefile", "index.ts", "App.tsx",
	"style.css", "Foo.java", "build.gradle", "setup.py", "LICENSE", "logo.PNG",
	"go.mod", "package-lock.json", "requirements-dev.txt", "app.cdx.json",
}

// BenchmarkListLockfiles walks a tree of 10,000 files in 50 directories.
func BenchmarkListLockfiles(b *testing.B) {
	root := b.TempDir()
	for d := range 50 {
		dir := filepath.Join(root, "pkg"+strconv.Itoa(d))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			b.Fatal(err)
		}
		for f := range 200 {
			name := strconv.Itoa(f) + "_" + benchNames[f%len(benchNames)]
			if f < len(benchNames) {
				name = benchNames[f]
			}
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ListLockfiles(root); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIsLockfile(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		for _, n := range benchNames {
			isLockfile(n)
		}
	}
}
