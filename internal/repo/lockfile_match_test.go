package repo

import (
	"path"
	"slices"
	"strings"
	"testing"
)

// isLockfileRef is the plain path.Match loop that isLockfile replaces.
func isLockfileRef(name string) bool {
	lower := strings.ToLower(name)
	for _, pat := range LockfileNames {
		if ok, _ := path.Match(pat, name); ok {
			return true
		}
		if ok, _ := path.Match(pat, lower); ok {
			return true
		}
	}
	return false
}

func TestNameMatcherSplit(t *testing.T) {
	m := newNameMatcher([]string{"go.mod", "*.pom", "*requirements*.txt", "pylock.*.toml"})
	if !m.exact["go.mod"] || len(m.exact) != 1 {
		t.Errorf("exact = %v", m.exact)
	}
	if len(m.suffixes) != 1 || m.suffixes[0] != ".pom" {
		t.Errorf("suffixes = %v", m.suffixes)
	}
	want := []glob{{"*requirements*.txt", "requirements"}, {"pylock.*.toml", "pylock."}}
	if !slices.Equal(m.globs, want) {
		t.Errorf("globs = %v, want %v", m.globs, want)
	}
}

func TestLongestLiteral(t *testing.T) {
	for p, want := range map[string]string{
		"*.spdx.*":        ".spdx.",
		"a?bc*d":          "bc",
		"x[ab]yyyy":       "",
		`x\*yyyy`:         "",
		"*":               "",
		"*requirements*.": "requirements",
	} {
		if got := longestLiteral(p); got != want {
			t.Errorf("longestLiteral(%q) = %q, want %q", p, got, want)
		}
	}
}

func TestIsLockfileMatchesReference(t *testing.T) {
	names := []string{
		"", ".", "go.mod", "GO.MOD", "go.mod.bak", "xgo.mod",
		"requirements.txt", "requirements-dev.txt", "dev-requirements.txt", "Requirements.TXT", "requirements.txt.orig",
		"pylock.toml", "pylock.dev.toml", "pylock..toml", "pylock.toml.x",
		"a.pom", ".pom", "a.POM", "pom.xml", "Pom.Xml",
		"app.deps.json", "app.csproj", "App.VBPROJ", "x.fsproj",
		"bom.json", "BOM.JSON", "bom.xml", "a.cdx.json", "a.CDX.XML", "a.spdx", "A.SPDX.JSON", "x.spdx.", "spdx",
		"Directory.Packages.props", "directory.packages.props",
		"main.go", "README.md", "package.json", "yarn.lock", "Cargo.lock", "cargo.lock",
		"İstanbul.spdx", "ǅ.cdx.json",
	}
	names = append(names, LockfileNames...)
	for _, n := range names {
		if got, want := isLockfile(n), isLockfileRef(n); got != want {
			t.Errorf("isLockfile(%q) = %v, want %v", n, got, want)
		}
	}
}

func FuzzIsLockfile(f *testing.F) {
	for _, s := range []string{"go.mod", "requirements-dev.txt", "A.SPDX.JSON", "pylock.x.toml", "main.go", "x.cdx.xml"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if strings.Contains(name, "/") {
			t.Skip("base names contain no '/'")
		}
		if got, want := isLockfile(name), isLockfileRef(name); got != want {
			t.Errorf("isLockfile(%q) = %v, want %v", name, got, want)
		}
	})
}
