// Package repo detects the repository root and lists its lockfiles.
package repo

import (
	"context"
	"io/fs"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jedipunkz/scomp/internal/model"
)

// LockfileNames are the file names used to compute the cache key. An entry is
// an exact base name or a path.Match glob on the base name. The list covers
// every file the scanner reads in its enabled plugins (lockfile, sbom,
// directory), so editing any of them invalidates the cache.
// Verified against osv-scanner v2.7.0 (osv-scalibr v0.5.4-0.20261009010329-5be78a00e3c2):
// the extractor presets in internal/scalibrplugin/presets.go and each
// extractor's FileRequired rule. Globs over-match where the extractor checks
// a directory or a longer suffix; over-matching only costs an extra rescan.
// Dependency extraction itself is done by the scanner.
var LockfileNames = []string{
	// Go
	"go.mod",
	// npm / pnpm / yarn / bun
	"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
	// Python
	"*requirements*.txt", "poetry.lock", "Pipfile.lock", "pdm.lock", "uv.lock", "pylock.toml", "pylock.*.toml",
	// Rust
	"Cargo.lock",
	// Ruby
	"Gemfile.lock", "gems.locked",
	// PHP
	"composer.lock",
	// Java / Gradle / Maven (verification-metadata.xml is only read under gradle/)
	"pom.xml", "*.pom", "gradle.lockfile", "buildscript-gradle.lockfile", "verification-metadata.xml",
	// .NET
	"packages.lock.json", "packages.config", "*.deps.json", "*.csproj", "*.vbproj", "*.fsproj",
	"Directory.Packages.props", "Directory.Build.props",
	// Dart / Flutter
	"pubspec.lock", "package_config.json",
	// Elixir
	"mix.lock",
	// R
	"renv.lock",
	// Swift
	"Package.resolved",
	// C / C++
	"conan.lock",
	// Haskell
	"cabal.project.freeze", "stack.yaml.lock",
	// osv-scanner custom dependency file
	"osv-scanner-custom.json",
	// SBOM (SPDX and CycloneDX name conventions; both extractors match case-insensitively)
	"bom.json", "bom.xml", "*.cdx.json", "*.cdx.xml", "*.spdx", "*.spdx.*",
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true}

// FindRoot returns the Git top-level directory containing path.
// If path is not inside a Git repository, it returns the absolute path and inGit=false.
func FindRoot(ctx context.Context, path string) (root string, inGit bool, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", false, err
	}
	out, err := exec.CommandContext(ctx, "git", "-C", abs, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return abs, false, nil
	}
	return filepath.Clean(strings.TrimSpace(string(out))), true, nil
}

// ListLockfiles returns the lockfiles under root as sorted slash-separated relative paths.
func ListLockfiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !isLockfile(d.Name()) {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	slices.Sort(files)
	return files, err
}

// isLockfile reports whether name matches an entry of LockfileNames. The SBOM
// extractors match names case-insensitively, so the lowercased name is also tested.
func isLockfile(name string) bool {
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

var scpLike = regexp.MustCompile(`^(?:[^@/]+@)?([^:/]+):(.+)$`)

// DisplayName returns a short name for root such as "github.com/owner/repo",
// derived from the origin remote. It falls back to root. The result is
// sanitized because the origin URL and root come from the repository and
// reach the terminal title.
func DisplayName(ctx context.Context, root string) string {
	out, err := exec.CommandContext(ctx, "git", "-C", root, "remote", "get-url", "origin").Output()
	if err != nil {
		return model.Sanitize(root)
	}
	if name := remoteName(model.Sanitize(strings.TrimSpace(string(out)))); name != "" {
		return name
	}
	return model.Sanitize(root)
}

func remoteName(url string) string {
	url = strings.TrimSuffix(url, ".git")
	if i := strings.Index(url, "://"); i >= 0 {
		rest := url[i+3:]
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		host, path, ok := strings.Cut(rest, "/")
		if !ok || path == "" {
			return ""
		}
		host, _, _ = strings.Cut(host, ":") // drop port
		return host + "/" + path
	}
	if m := scpLike.FindStringSubmatch(url); m != nil {
		return m[1] + "/" + strings.TrimPrefix(m[2], "/")
	}
	return ""
}
