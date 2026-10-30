// Package repo detects the repository root and lists its lockfiles.
package repo

import (
	"context"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
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

// skipDirs are directory names that are never walked. osv-scanner v2.7.0 has
// no built-in directory name list (it skips only --experimental-exclude and
// .gitignore matches); these names predate the .gitignore check below.
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
//
// Paths matched by a .gitignore file under root are skipped, as the scanner
// skips them: osv-scanner v2.7.0 sets osv-scalibr's UseGitignore (unless
// --no-ignore), and osv-scalibr's walker neither descends into an ignored
// directory nor reads an ignored file. Patterns are parsed the same way as
// osv-scalibr's extractor/filesystem/internal/gitignore.go. .gitignore files
// above root are not read; osv-scanner applies those too, so this walk skips
// a subset of what the scanner skips and never drops a file the scanner reads
// from the cache key.
func ListLockfiles(root string) ([]string, error) {
	var files []string
	err := walkLockfiles(root, nil, nil, &files)
	slices.Sort(files)
	return files, err
}

// walkLockfiles appends the lockfiles under dir to files. rel is dir relative
// to the walk root as path components; ignores holds the .gitignore matchers
// of dir's ancestors up to the walk root.
func walkLockfiles(dir string, rel []string, ignores []gitignore.Matcher, files *[]string) error {
	if m := readGitignore(dir, rel); m != nil {
		ignores = append(ignores[:len(ignores):len(ignores)], m)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		childRel := append(rel[:len(rel):len(rel)], name)
		switch {
		case e.IsDir():
			if skipDirs[name] || ignored(ignores, childRel, true) {
				continue
			}
			if err := walkLockfiles(filepath.Join(dir, name), childRel, ignores, files); err != nil {
				return err
			}
		case e.Type().IsRegular() && isLockfile(name) && !ignored(ignores, childRel, false):
			*files = append(*files, strings.Join(childRel, "/"))
		}
	}
	return nil
}

// readGitignore parses dir/.gitignore like osv-scalibr's ParseDirForGitignore.
// It returns nil when the file is missing or unreadable: skipping less is
// always safe for the cache key.
func readGitignore(dir string, rel []string) gitignore.Matcher {
	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		return nil
	}
	var ps []gitignore.Pattern
	for line := range strings.Lines(string(data)) {
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "#") && strings.TrimSpace(line) != "" {
			ps = append(ps, gitignore.ParsePattern(line, rel))
		}
	}
	if len(ps) == 0 {
		return nil
	}
	return gitignore.NewMatcher(ps)
}

// ignored reports whether any matcher ignores p, like osv-scalibr's GitignoreMatch.
func ignored(ignores []gitignore.Matcher, p []string, isDir bool) bool {
	for _, m := range ignores {
		if m.Match(p, isDir) {
			return true
		}
	}
	return false
}

// lockfiles is LockfileNames split once, because isLockfile runs for every
// file in the repository before the TUI starts.
var lockfiles = newNameMatcher(LockfileNames)

// nameMatcher matches base names against path.Match patterns. Patterns
// without metacharacters become a map lookup and "*<literal>" patterns a
// suffix test; only the rest go through path.Match, after a quick reject on
// their longest literal run. A suffix test equals path.Match because base
// names contain no '/'.
type nameMatcher struct {
	exact    map[string]bool
	suffixes []string
	globs    []glob
}

type glob struct {
	pattern string
	literal string // every match contains it; empty when unknown
}

const globMeta = `*?[\`

func newNameMatcher(patterns []string) nameMatcher {
	m := nameMatcher{exact: map[string]bool{}}
	for _, p := range patterns {
		switch {
		case !strings.ContainsAny(p, globMeta):
			m.exact[p] = true
		case p[0] == '*' && !strings.ContainsAny(p[1:], globMeta):
			m.suffixes = append(m.suffixes, p[1:])
		default:
			m.globs = append(m.globs, glob{pattern: p, literal: longestLiteral(p)})
		}
	}
	return m
}

// longestLiteral returns the longest run of p between '*' and '?'. It returns
// "" when p has a character class or an escape, whose text is not literal.
func longestLiteral(p string) string {
	if strings.ContainsAny(p, `[\`) {
		return ""
	}
	var lit string
	for _, s := range strings.FieldsFunc(p, func(r rune) bool { return r == '*' || r == '?' }) {
		if len(s) > len(lit) {
			lit = s
		}
	}
	return lit
}

func (m nameMatcher) match(name string) bool {
	if m.exact[name] {
		return true
	}
	for _, s := range m.suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	for _, g := range m.globs {
		if !strings.Contains(name, g.literal) {
			continue
		}
		if ok, _ := path.Match(g.pattern, name); ok {
			return true
		}
	}
	return false
}

// isLockfile reports whether name matches an entry of LockfileNames. The SBOM
// extractors match names case-insensitively, so the lowercased name is also tested.
func isLockfile(name string) bool {
	if lockfiles.match(name) {
		return true
	}
	lower := strings.ToLower(name)
	return lower != name && lockfiles.match(lower)
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
