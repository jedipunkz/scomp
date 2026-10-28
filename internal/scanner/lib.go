package scanner

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"

	"github.com/google/osv-scanner/v2/pkg/osvscanner"

	"github.com/jedipunkz/scomp/internal/model"
)

// LibError is returned when the embedded osv-scanner fails.
type LibError struct {
	Err error
	Log string // log lines emitted by osv-scanner during the scan
}

func (e *LibError) Error() string   { return "osv-scanner: " + e.Err.Error() }
func (e *LibError) Unwrap() error   { return e.Err }
func (e *LibError) Details() string { return e.Log }

// Lib runs osv-scanner in-process via osv-scanner/v2/pkg/osvscanner.
type Lib struct {
	Offline bool
}

// osvscanner logs through a process-global logger, so scans are serialized
// and the log is captured into a buffer instead of corrupting the TUI.
var (
	libMu     sync.Mutex
	libLog    syncBuffer
	libLogger sync.Once
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) take() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.buf.String()
	b.buf.Reset()
	return s
}

// Actions returns the scanner actions equivalent to
// `osv-scanner scan source -r <root>` (plus the --offline flags of Exec).
func (l Lib) Actions(root string) osvscanner.ScannerActions {
	a := osvscanner.ScannerActions{
		DirectoryPaths: []string{root},
		Recursive:      true,
		// Same as the CLI default (stable analyses only).
		CallAnalysisStates: map[string]bool{"go": true, "rust": false, "jar": false},
	}
	a.PluginsEnabled = []string{"lockfile", "sbom", "directory"}
	a.RequestUserAgent = "scomp"
	if l.Offline {
		a.CompareOffline = true
		a.DownloadDatabases = true
		a.TransitiveScanning.Disabled = true
	}
	return a
}

func (l Lib) Scan(ctx context.Context, root string) ([]model.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	libLogger.Do(func() {
		osvscanner.SetLogger(slog.NewTextHandler(&libLog, &slog.HandlerOptions{Level: slog.LevelWarn}))
	})

	type result struct {
		findings []model.Finding
		log      string
		err      error
	}
	done := make(chan result, 1)
	go func() {
		// DoScan takes no context; on cancel the goroutine finishes in the
		// background and its result is dropped.
		libMu.Lock()
		defer libMu.Unlock()
		libLog.take()
		res, err := osvscanner.DoScan(l.Actions(root))
		log := libLog.take()
		if err != nil && !errors.Is(err, osvscanner.ErrVulnerabilitiesFound) {
			done <- result{log: log, err: err}
			return
		}
		done <- result{findings: convert(&res, root), log: log}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		switch {
		case errors.Is(r.err, osvscanner.ErrNoPackagesFound):
			return nil, model.ErrNoLockfiles
		case r.err != nil:
			return nil, &LibError{Err: r.err, Log: r.log}
		}
		return r.findings, nil
	}
}
