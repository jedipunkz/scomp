package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/jedipunkz/scomp/internal/model"
)

const InstallHint = "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest"

// ErrNotInstalled means osv-scanner was not found in PATH.
var ErrNotInstalled = errors.New("osv-scanner not found in PATH; install it with: " + InstallHint)

// ExecError is returned when osv-scanner exits with an unexpected code.
type ExecError struct {
	ExitCode int
	Stderr   string
}

func (e *ExecError) Error() string {
	return fmt.Sprintf("osv-scanner exited with code %d", e.ExitCode)
}

// Details returns the full stderr of osv-scanner.
func (e *ExecError) Details() string { return e.Stderr }

// Exec runs the osv-scanner binary and parses its JSON output.
type Exec struct {
	Path    string // resolved absolute path of osv-scanner
	Offline bool
}

// NewExec resolves osv-scanner from PATH.
func NewExec(offline bool) (*Exec, error) {
	p, err := exec.LookPath("osv-scanner")
	if err != nil {
		return nil, ErrNotInstalled
	}
	return &Exec{Path: p, Offline: offline}, nil
}

// Args returns the osv-scanner arguments for scanning root.
func (e *Exec) Args(root string) []string {
	// Call analysis is off, as in Lib.Actions.
	args := []string{"scan", "source", "-r", root, "--format", "json", "--no-call-analysis=go"}
	if e.Offline {
		// Only the vulnerability database is downloaded; package names
		// are not sent to osv.dev or deps.dev.
		args = append(args, "--offline-vulnerabilities", "--download-offline-databases", "--no-resolve")
	}
	return args
}

func (e *Exec) Scan(ctx context.Context, root string) ([]model.Finding, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.Path, e.Args(root)...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, fmt.Errorf("run osv-scanner: %w", err)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		code = exitErr.ExitCode()
	}

	switch code {
	case 0, 1: // 0: no vulnerabilities, 1: vulnerabilities found
		findings, err := Parse(stdout.Bytes(), root)
		if err != nil {
			return nil, &ExecError{ExitCode: code, Stderr: stderr.String() + "\n" + err.Error()}
		}
		return findings, nil
	case 128: // no packages found
		return nil, model.ErrNoLockfiles
	default:
		return nil, &ExecError{ExitCode: code, Stderr: stderr.String()}
	}
}
