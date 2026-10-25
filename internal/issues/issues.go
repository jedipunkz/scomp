// Package issues creates GitHub issues for findings with the gh CLI. gh must
// be installed and authenticated; every value is passed to gh as an argument,
// never through a shell or an editor, and gh's own output is data, not
// instructions.
package issues

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/jedipunkz/scomp/internal/model"
)

// defaultBin is the gh binary; tests override Bin.
const defaultBin = "gh"

// Client runs gh against the git repository at Dir. The GitHub repository is
// derived from the git remotes there, like plain gh usage.
type Client struct {
	// Bin is the gh binary. Empty means "gh".
	Bin string
	// Dir is the working directory for gh. Empty means the process cwd.
	Dir string
	// Scomp is the scomp version noted in the generated issue body.
	Scomp string
}

// Issue is a GitHub issue matched by Search.
type Issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
	URL    string `json:"url"`
}

// Search lists open and closed issues whose title contains the finding's OSV
// ID and package name, newest first.
func (c Client) Search(ctx context.Context, f model.Finding) ([]Issue, error) {
	query := fmt.Sprintf("%q %q in:title", f.ID, f.Package.Name)
	out, _, err := c.run(ctx, "issue", "list", "--state", "all", "--search", query,
		"--json", "number,title,state,url", "--limit", "20")
	if err != nil {
		return nil, err
	}
	var issues []Issue
	if err := json.Unmarshal(out, &issues); err != nil {
		return nil, fmt.Errorf("gh issue list: unexpected output: %w", err)
	}
	slices.SortFunc(issues, func(a, b Issue) int { return b.Number - a.Number })
	return issues, nil
}

// Create opens a new GitHub issue for the finding and returns its URL.
func (c Client) Create(ctx context.Context, f model.Finding) (string, error) {
	title, body, err := render(f, c.Scomp)
	if err != nil {
		return "", fmt.Errorf("render issue: %w", err)
	}
	out, _, err := c.run(ctx, "issue", "create", "--title", title, "--body", body)
	if err != nil {
		return "", err
	}
	return issueURL(out)
}

// Edit overrides the title and body of an existing issue with a fresh render
// for the finding and returns its URL. It does not reopen a closed issue.
func (c Client) Edit(ctx context.Context, f model.Finding, number int) (string, error) {
	title, body, err := render(f, c.Scomp)
	if err != nil {
		return "", fmt.Errorf("render issue: %w", err)
	}
	out, _, err := c.run(ctx, "issue", "edit", strconv.Itoa(number), "--title", title, "--body", body)
	if err != nil {
		return "", err
	}
	return issueURL(out)
}

// run executes gh with args and returns its stdout and stderr.
func (c Client) run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	bin := c.Bin
	if bin == "" {
		bin = defaultBin
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204 excluded; gh runs from PATH like git
	cmd.Dir = c.Dir
	// gh must never prompt inside the TUI: no stdin, prompts disabled.
	cmd.Stdin = nil
	cmd.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1")
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		switch {
		case errors.Is(err, exec.ErrNotFound):
			return nil, nil, fmt.Errorf("%s: command not found; install the GitHub CLI (https://cli.github.com)", bin)
		case strings.TrimSpace(errOut.String()) != "":
			return nil, nil, fmt.Errorf("gh %s %s: %s", args[0], args[1], firstLine(errOut.String()))
		default:
			return nil, nil, fmt.Errorf("gh %s %s: %w", args[0], args[1], err)
		}
	}
	return out.Bytes(), errOut.Bytes(), nil
}

// issueURL extracts the issue URL from gh's stdout (the last non-empty line).
func issueURL(out []byte) (string, error) {
	lines := strings.Split(string(out), "\n")
	slices.Reverse(lines)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "https://") {
			return "", fmt.Errorf("gh: unexpected output: %s", firstLine(string(out)))
		}
		return line, nil
	}
	return "", errors.New("gh: no issue URL in output")
}

// firstLine returns the first non-empty line of s.
func firstLine(s string) string {
	for line := range strings.SplitSeq(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

//go:embed issue.tmpl
var tmplSrc string

var tmpl = template.Must(template.New("issue").Parse(tmplSrc))

// data is the fully prepared template input; the template only formats it.
type data struct {
	ID         string
	CVEs       string
	Package    string
	Version    string
	Ecosystem  string
	Source     string
	Severity   string
	Score      string
	Fixed      string
	Summary    string
	Details    string
	References []string
	Published  string
	Scomp      string
}

// render renders the issue title and body for a finding. The finding is
// sanitized here too: its strings come from OSV data and lockfiles and must
// not carry escape sequences into the issue body.
func render(f model.Finding, scomp string) (string, string, error) {
	f = model.SanitizeFinding(f)
	d := data{
		ID:         f.ID,
		CVEs:       joinOr(f.CVEs, "none"),
		Package:    f.Package.Name,
		Version:    f.Package.Version,
		Ecosystem:  f.Package.Ecosystem,
		Source:     f.Package.Source,
		Severity:   f.Severity.String(),
		Fixed:      joinOr(f.FixedVersions, "none"),
		Summary:    strings.TrimSpace(f.Summary),
		Details:    strings.TrimSpace(f.Details),
		References: f.References,
		Scomp:      scomp,
	}
	if d.Source == "" {
		d.Source = "unknown"
	}
	if f.CVSSScore > 0 {
		d.Score = fmt.Sprintf(" (CVSS %.1f)", f.CVSSScore)
	}
	if !f.Published.IsZero() {
		d.Published = f.Published.Format("2006-01-02")
	}
	var title, body bytes.Buffer
	if err := tmpl.ExecuteTemplate(&title, "title", d); err != nil {
		return "", "", err
	}
	if err := tmpl.ExecuteTemplate(&body, "body", d); err != nil {
		return "", "", err
	}
	return title.String(), body.String(), nil
}

func joinOr(ss []string, none string) string {
	if len(ss) == 0 {
		return none
	}
	return strings.Join(ss, ", ")
}
