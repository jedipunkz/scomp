// Command scomp browses known vulnerabilities in the current repository's dependencies.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
	"unicode"

	tea "charm.land/bubbletea/v2"

	"github.com/jedipunkz/scomp/internal/cache"
	"github.com/jedipunkz/scomp/internal/issues"
	"github.com/jedipunkz/scomp/internal/model"
	"github.com/jedipunkz/scomp/internal/repo"
	"github.com/jedipunkz/scomp/internal/scanner"
	"github.com/jedipunkz/scomp/internal/tui"
)

// version is set with -ldflags "-X main.version=...".
var version = ""

type options struct {
	path     string
	noCache  bool
	cacheTTL time.Duration
	offline  bool
	scanner  string
	json     bool
	version  bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "scomp:", err)
		}
		os.Exit(1)
	}
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("scomp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: scomp [flags] [path]")
		fs.PrintDefaults()
	}
	fs.BoolVar(&o.noCache, "no-cache", false, "do not read or write the cache")
	fs.DurationVar(&o.cacheTTL, "cache-ttl", 24*time.Hour, "cache TTL")
	fs.BoolVar(&o.offline, "offline", false, "use osv-scanner's offline vulnerability DB (dependency info is not sent externally)")
	fs.StringVar(&o.scanner, "scanner", "lib", "scanner implementation: lib (embedded osv-scanner) | exec (osv-scanner in PATH)")
	fs.BoolVar(&o.json, "json", false, "print findings as JSON to stdout instead of starting the TUI")
	fs.BoolVar(&o.version, "version", false, "print version")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	switch fs.NArg() {
	case 0:
		o.path = "."
	case 1:
		o.path = fs.Arg(0)
	default:
		fs.Usage()
		return o, fmt.Errorf("expected at most one path, got %d", fs.NArg())
	}
	if o.cacheTTL < 0 {
		return o, errors.New("--cache-ttl must not be negative")
	}
	return o, nil
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	o, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	if o.version {
		_, _ = fmt.Fprintln(stdout, "scomp", versionString())
		return nil
	}

	root, inGit, err := repo.FindRoot(ctx, o.path)
	if err != nil {
		return err
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}
	if !inGit {
		_, _ = fmt.Fprintf(stderr, "warning: %s is not in a git repository; scanning it as the root\n", model.Sanitize(root))
	}

	sc, scannerPath, err := newScanner(o)
	if err != nil {
		return err
	}

	lockfiles, err := repo.ListLockfiles(root)
	if err != nil {
		return fmt.Errorf("list lockfiles: %w", err)
	}

	var store *cache.Store
	var key string
	if !o.noCache {
		if store, err = cache.DefaultStore(); err != nil {
			_, _ = fmt.Fprintf(stderr, "warning: cache disabled: %v\n", model.Sanitize(err.Error()))
			store = nil
		} else if key, err = cache.Key(root, scannerID(scannerPath, o.offline), lockfiles); err != nil {
			_, _ = fmt.Fprintf(stderr, "warning: cache disabled: %v\n", model.Sanitize(err.Error()))
			store = nil
		}
	}

	var cached *cache.Entry
	var notice string
	if store != nil {
		e, ok, err := store.Load(root, key, o.cacheTTL)
		switch {
		case err != nil:
			notice = "cache: " + err.Error()
			_, _ = fmt.Fprintln(stderr, "warning:", model.Sanitize(notice))
		case ok:
			cached = &e
		}
	}

	save := func(fs []model.Finding) error {
		if store == nil {
			return nil
		}
		_, err := store.Save(root, key, fs)
		return err
	}

	ghc := issues.Client{Dir: root, Scomp: strings.TrimPrefix(versionString(), "v")}

	if o.json {
		return runJSON(ctx, sc, root, cached, save, stdout, stderr)
	}

	cfg := tui.Config{
		Title:       repo.DisplayName(ctx, root),
		ScannerPath: scannerPath,
		Lockfiles:   repo.LockfileNames,
		Notice:      notice,
		Scan: func(ctx context.Context) ([]model.Finding, error) {
			fs, err := sc.Scan(ctx, root)
			if errors.Is(err, scanner.ErrNoPackages) {
				return nil, tui.ErrNoLockfiles
			}
			return fs, err
		},
		OnScanned: save,
		OpenURL:   openBrowser,
		SearchIssues: func(ctx context.Context, f model.Finding) ([]tui.ExistingIssue, error) {
			ms, err := ghc.Search(ctx, f)
			if err != nil {
				return nil, err
			}
			issues := make([]tui.ExistingIssue, len(ms))
			for i, m := range ms {
				issues[i] = tui.ExistingIssue{Number: m.Number, Title: m.Title, State: m.State, URL: m.URL}
			}
			return issues, nil
		},
		CreateIssue: ghc.Create,
		EditIssue:   ghc.Edit,
		ScanOnStart: cached == nil,
	}
	if cached != nil {
		cfg.Findings = cached.Findings
		cfg.CachedAt = cached.CreatedAt
	}
	_, err = tea.NewProgram(tui.New(ctx, cfg), tea.WithContext(ctx)).Run()
	if errors.Is(err, tea.ErrInterrupted) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// scannerID identifies everything besides the lockfiles that changes scan
// results: the scomp version (parsing), the scanner and its version, and the
// offline mode.
func scannerID(scannerPath string, offline bool) string {
	return fmt.Sprintf("scomp %s; %s; offline=%t", versionString(), scannerPath, offline)
}

func newScanner(o options) (scanner.Scanner, string, error) {
	switch o.scanner {
	case "exec":
		e, err := scanner.NewExec(o.offline)
		if err != nil {
			return nil, "", err
		}
		return e, e.Path, nil
	case "lib":
		return scanner.Lib{Offline: o.offline}, "osv-scanner " + embeddedOSVVersion() + " (embedded)", nil
	default:
		return nil, "", fmt.Errorf("unknown --scanner %q (want lib or exec)", o.scanner)
	}
}

func runJSON(ctx context.Context, sc scanner.Scanner, root string, cached *cache.Entry, save func([]model.Finding) error, stdout, stderr io.Writer) error {
	var findings []model.Finding
	if cached != nil {
		findings = cached.Findings
	} else {
		fs, err := sc.Scan(ctx, root)
		switch {
		case errors.Is(err, scanner.ErrNoPackages):
			_, _ = fmt.Fprintln(stderr, "scomp:", model.Sanitize(err.Error()))
		case err != nil:
			var d interface{ Details() string }
			if errors.As(err, &d) && d.Details() != "" {
				_, _ = fmt.Fprintln(stderr, strings.TrimRight(model.Sanitize(d.Details()), "\n"))
			}
			return err
		default:
			findings = fs
			if err := save(fs); err != nil {
				_, _ = fmt.Fprintln(stderr, "warning: cache write failed:", model.Sanitize(err.Error()))
			}
		}
	}
	tui.SortFindings(findings)
	if findings == nil {
		findings = []model.Finding{}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch {
	case runtime.GOOS == "darwin":
		cmd = exec.Command("open", url)
	case runtime.GOOS == "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case inWSL(os.Getenv, procVersion):
		c, err := wslOpen(url)
		if err != nil {
			return err
		}
		cmd = c
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() //nolint:errcheck // reap the child; its exit status is not actionable
	return nil
}

// procVersion is the path checked for a WSL kernel signature.
const procVersion = "/proc/version"

// inWSL reports whether the process runs inside WSL: WSL_DISTRO_NAME is set
// on WSL2, and /proc/version mentions Microsoft on both WSL1 and WSL2.
func inWSL(getenv func(string) string, procVersionPath string) bool {
	if getenv("WSL_DISTRO_NAME") != "" {
		return true
	}
	b, err := os.ReadFile(procVersionPath)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(b)), "microsoft")
}

// wslOpen builds the command that opens url with the Windows-side browser.
// wslview (from wslu) is preferred; cmd.exe start is the fallback when wslu
// is not installed. cmd.exe is unavailable when WSL interop is disabled, and
// openBrowser reports the Start error through the TUI status line.
func wslOpen(url string) (*exec.Cmd, error) {
	if _, err := exec.LookPath("wslview"); err == nil {
		return exec.Command("wslview", url), nil
	}
	return cmdStartCommand(url)
}

// cmdStartCommand builds the cmd.exe fallback. cmd.exe interprets & | ^ < > %
// and " in the command line even when Go quotes the argument, so a URL with
// any of them could run arbitrary commands. The parser already drops such
// OSV IDs; this check refuses them here as well.
func cmdStartCommand(url string) (*exec.Cmd, error) {
	if strings.ContainsAny(url, `&|^<>%"`) || strings.IndexFunc(url, unicode.IsControl) >= 0 {
		return nil, errors.New("refusing to open URL with cmd.exe: it contains cmd.exe metacharacters or control characters")
	}
	return exec.Command("cmd.exe", "/c", "start", "", url), nil
}

func versionString() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// embeddedOSVVersion returns the version of the linked osv-scanner module.
func embeddedOSVVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/google/osv-scanner/v2" {
				return d.Version
			}
		}
	}
	return "unknown"
}
