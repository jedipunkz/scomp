// Package repo detects the repository root and lists its lockfiles.
package repo

import (
	"context"
	"io/fs"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/jedipunkz/scomp/internal/model"
)

// LockfileNames are the files used to compute the cache key.
// Dependency extraction itself is done by the scanner.
var LockfileNames = []string{
	// Go
	"go.mod",
	// npm / pnpm / yarn
	"package-lock.json", "pnpm-lock.yaml", "yarn.lock",
	// Python
	"requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock",
	// Rust
	"Cargo.lock",
	// Ruby
	"Gemfile.lock",
	// PHP
	"composer.lock",
	// Java
	"pom.xml", "gradle.lockfile",
	// .NET
	"packages.lock.json",
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
		if !d.Type().IsRegular() || !slices.Contains(LockfileNames, d.Name()) {
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
