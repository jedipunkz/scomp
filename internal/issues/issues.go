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
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"unicode"

	"github.com/jedipunkz/scomp/internal/model"
)

// defaultBin is the gh binary; tests override Bin.
const defaultBin = "gh"

// securityLabel is the GitHub label applied to issues scomp creates. It is
// created on demand when the repository does not have it yet.
const securityLabel = "security"

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

// Create opens a new GitHub issue for the finding and returns its URL. The
// issue carries the security label; ensureLabel creates that label when the
// repository does not have it yet.
func (c Client) Create(ctx context.Context, f model.Finding) (string, error) {
	if err := c.ensureLabel(ctx); err != nil {
		return "", err
	}
	title, body, err := render(f, c.Scomp)
	if err != nil {
		return "", fmt.Errorf("render issue: %w", err)
	}
	out, _, err := c.run(ctx, "issue", "create", "--title", title, "--body", body,
		"--label", securityLabel)
	if err != nil {
		return "", err
	}
	return issueURL(out)
}

// ensureLabel creates the security label unless the repository already has
// one. gh label list --search also matches descriptions, so the exact name is
// checked here.
func (c Client) ensureLabel(ctx context.Context) error {
	out, _, err := c.run(ctx, "label", "list", "--search", securityLabel,
		"--json", "name", "--limit", "100")
	if err != nil {
		return err
	}
	// gh label list --search prints nothing (not even []) when nothing
	// matches; treat empty output as "label missing".
	if trimmed := bytes.TrimSpace(out); len(trimmed) != 0 {
		var labels []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(trimmed, &labels); err != nil {
			return fmt.Errorf("gh label list: unexpected output: %w", err)
		}
		for _, l := range labels {
			if l.Name == securityLabel {
				return nil
			}
		}
	}
	if _, _, err := c.run(ctx, "label", "create", securityLabel,
		"--color", "d73a4a", "--description", "Security vulnerabilities found by scomp"); err != nil {
		return err
	}
	return nil
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
			return nil, nil, fmt.Errorf("gh %s %s: %s", args[0], args[1], firstNonEmptyLine(errOut.String()))
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
			return "", fmt.Errorf("gh: unexpected output: %s", firstNonEmptyLine(string(out)))
		}
		return line, nil
	}
	return "", errors.New("gh: no issue URL in output")
}

// firstNonEmptyLine returns the first non-empty line of s.
func firstNonEmptyLine(s string) string {
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
// Every attacker-influenced string is Markdown-escaped or wrapped in a code
// span here, so the template never has to know about escaping.
type data struct {
	ID         string
	IDPath     string
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

// titleData is the issue title input. A title is plain text, not Markdown, so
// it takes the sanitized values unescaped.
type titleData struct {
	ID      string
	Package string
	Version string
}

// render renders the issue title and body for a finding. The finding is
// sanitized here too: its strings come from OSV data and lockfiles and must
// not carry escape sequences into the issue body.
func render(f model.Finding, scomp string) (string, string, error) {
	f = model.SanitizeFinding(f)
	source := f.Package.Source
	if source == "" {
		source = "unknown"
	}
	d := data{
		ID:         tableCell(f.ID),
		IDPath:     url.PathEscape(f.ID),
		CVEs:       tableCell(joinOr(f.CVEs, "none")),
		Package:    codeCell(f.Package.Name),
		Version:    codeCell(f.Package.Version),
		Ecosystem:  tableCell(f.Package.Ecosystem),
		Source:     codeCell(source),
		Severity:   f.Severity.String(),
		Fixed:      tableCell(joinOr(f.FixedVersions, "none")),
		Summary:    escapeProse(strings.TrimSpace(f.Summary)),
		Details:    escapeProse(strings.TrimSpace(f.Details)),
		References: references(f.References),
		Scomp:      scomp,
	}
	d.Score = model.CVSSSuffix(f.CVSSScore)
	if !f.Published.IsZero() {
		d.Published = f.Published.Format("2006-01-02")
	}
	var title, body bytes.Buffer
	t := titleData{ID: f.ID, Package: f.Package.Name, Version: f.Package.Version}
	if err := tmpl.ExecuteTemplate(&title, "title", t); err != nil {
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

// mdEscaper backslash-escapes the characters that can start Markdown
// structure or pings anywhere in a line. The `://` and `www.` rules stop bare
// URLs from becoming autolinks. Backslash-escaped ASCII punctuation renders as
// the bare character on GitHub.
var mdEscaper = strings.NewReplacer(
	`\`, `\\`, "`", "\\`", "*", `\*`, "_", `\_`, "~", `\~`,
	"[", `\[`, "]", `\]`, "(", `\(`, ")", `\)`, "<", `\<`, ">", `\>`,
	"!", `\!`, "#", `\#`, "|", `\|`, "@", `\@`,
	"://", `\://`, "www.", `www\.`,
)

// escapeProse escapes free text (Summary, Details) so it renders as literal
// text and cannot form links, images, headings, lists, code fences or HTML.
func escapeProse(s string) string {
	lines := strings.Split(mdEscaper.Replace(s), "\n")
	for i, line := range lines {
		lines[i] = escapeLineStart(line)
	}
	return strings.Join(lines, "\n")
}

// escapeLineStart escapes the markers that start a block at the beginning of
// a line: list bullets (`-`, `+`), setext underlines (`=`) and ordered list
// numbers (`1.`, `1)`). Backslash-escaping `*`, `#` and `>` is already done by
// mdEscaper.
func escapeLineStart(line string) string {
	body := strings.TrimLeft(line, " ")
	if body == "" {
		return line
	}
	indent := line[:len(line)-len(body)]
	switch body[0] {
	case '-', '+', '=':
		return indent + `\` + body
	}
	n := 0
	for n < len(body) && body[n] >= '0' && body[n] <= '9' {
		n++
	}
	if n > 0 && n < len(body) && (body[n] == '.' || body[n] == ')') {
		return indent + body[:n] + `\` + body[n:]
	}
	return line
}

// oneLine joins the lines of s with spaces. Table cells and list items cannot
// span lines.
func oneLine(s string) string {
	return strings.ReplaceAll(s, "\n", " ")
}

// tableCell escapes a single-line value for a table cell or prose-like field.
func tableCell(s string) string {
	return mdEscaper.Replace(oneLine(s))
}

// codeSpan wraps s in an inline code span. The fence is one backtick longer
// than the longest backtick run in s, so no backtick in s closes the span.
func codeSpan(s string) string {
	s = oneLine(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	if longest > 0 {
		s = " " + s + " "
	}
	return fence + s + fence
}

// codeCell is codeSpan for a table cell: a pipe must be escaped even inside a
// code span, or it splits the cell.
func codeCell(s string) string {
	return codeSpan(strings.ReplaceAll(s, "|", `\|`))
}

// references returns the reference list items. A value that is a plain
// http(s) URL is kept bare so GitHub autolinks it. Anything else becomes a
// code span, so it cannot form Markdown.
func references(refs []string) []string {
	var out []string
	for _, r := range refs {
		r = oneLine(r)
		if !isPlainURL(r) {
			r = codeSpan(r)
		}
		out = append(out, r)
	}
	return out
}

// isPlainURL reports whether s is an absolute http(s) URL with no whitespace
// and no character that starts Markdown structure.
func isPlainURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return false
	}
	return !strings.ContainsAny(s, "<>[]\\`*~|") && !strings.ContainsFunc(s, unicode.IsSpace)
}
