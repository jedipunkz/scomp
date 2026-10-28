// Package tui implements the interactive finding browser.
package tui

import (
	"context"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/jedipunkz/scomp/internal/model"
)

// Config wires the TUI to the other layers.
type Config struct {
	Title       string // repository display name
	ScannerPath string // resolved scanner binary shown in the header
	Lockfiles   []string

	// Initial findings from the cache. CachedAt is zero when there is no cache hit.
	Findings []model.Finding
	CachedAt time.Time

	// Notice is shown in the status line at startup (e.g. a cache warning).
	Notice string

	// Scan runs a fresh scan. It is called from a tea.Cmd goroutine.
	Scan func(ctx context.Context) ([]model.Finding, error)
	// OnScanned is called after a successful scan, e.g. to write the cache.
	OnScanned func([]model.Finding) error
	// OpenURL opens a URL in the browser.
	OpenURL func(url string) error
	// SearchIssues finds existing GitHub issues for a finding (OSV ID and
	// package name in the title), newest first. It is called from a tea.Cmd
	// goroutine. Nil disables alt+i.
	SearchIssues func(ctx context.Context, f model.Finding) ([]ExistingIssue, error)
	// CreateIssue opens a new GitHub issue for a finding and returns its URL.
	CreateIssue func(ctx context.Context, f model.Finding) (string, error)
	// EditIssue overrides an existing issue's title and body with a fresh
	// render of the finding and returns the issue URL.
	EditIssue func(ctx context.Context, f model.Finding, number int) (string, error)
	// ScanOnStart starts a scan immediately (no cache hit).
	ScanOnStart bool

	Now func() time.Time
}

type severityFilter int

const (
	sevAll severityFilter = iota
	sevCritical
	sevHighPlus
	sevMediumPlus
	sevFilterCount
)

func (s severityFilter) min() model.Severity {
	switch s {
	case sevCritical:
		return model.SeverityCritical
	case sevHighPlus:
		return model.SeverityHigh
	case sevMediumPlus:
		return model.SeverityMedium
	default:
		return model.SeverityUnknown
	}
}

func (s severityFilter) label() string {
	switch s {
	case sevCritical:
		return "critical"
	case sevHighPlus:
		return "high+"
	case sevMediumPlus:
		return "medium+"
	default:
		return "all"
	}
}

type Model struct {
	cfg Config
	ctx context.Context

	input   textinput.Model
	preview viewport.Model
	spin    spinner.Model
	help    help.Model

	findings []model.Finding // sanitized, sorted
	norm     []Normalized    // precomputed lowercase text, same order as findings
	layouts  []keyLayout
	ecos     []string

	// per-render aggregates, reset and recomputed in setFindings when the findings change
	sevCounts [model.SeverityCritical + 1]int
	nameMaxW  int
	verMaxW   int
	idMaxW    int

	results []Result
	terms   []string // folded free-text terms of the current query; view.go highlights them
	cursor  int
	offset  int // first visible row in the list

	sev       severityFilter
	eco       int // 0 = all, otherwise index+1 into ecos
	fixedOnly bool

	scanning    bool
	cancelScan  context.CancelFunc
	scanErr     error
	noLockfiles bool
	cachedAt    time.Time
	status      string

	width  int
	height int

	// preview content cache key; re-rendered when any of these change
	previewFor   int // finding index; -1 none
	previewWidth int
	previewErr   bool

	// GitHub issue flow (alt+i); see issuePromptKey and view.go.
	issueState   issueState
	issueFinding model.Finding   // finding the prompt is about
	issueFound   []ExistingIssue // existing matches, newest first
	issueSeq     int             // incremented per search; drops stale results

	focusCmd tea.Cmd
}

// previewInvalid forces the preview to be re-rendered.
const previewInvalid = -2

var timeZero time.Time

type scanDoneMsg struct {
	findings []model.Finding
	err      error
}

type openedMsg struct{ err error }

// ExistingIssue is a GitHub issue found by SearchIssues for a finding.
type ExistingIssue struct {
	Number int // issue number
	Title  string
	State  string // GitHub issue state as reported by gh, e.g. "open"
	URL    string
}

// issueState is the state of the GitHub issue flow (alt+i). Prompt states
// take over the whole view and swallow all other keys.
type issueState int

const (
	issueIdle      issueState = iota // alt+i starts a search
	issueSearching                   // SearchIssues is running
	issueConfirm                     // no existing issue: y creates, c cancels
	issueChoose                      // existing issue: o overrides, d duplicates, c cancels
	issueRunning                     // gh issue create/edit is running
)

type issueAction int

const (
	issueCreate issueAction = iota
	issueEdit
)

type issuesSearchedMsg struct {
	seq     int // sequence of the search this result belongs to
	finding model.Finding
	issues  []ExistingIssue
	err     error
}

type issueDoneMsg struct {
	action issueAction
	number int // edited issue number, for issueEdit
	url    string
	err    error
}

// New builds the TUI model. ctx cancels running scans.
func New(ctx context.Context, cfg Config) Model {
	ti := textinput.New()
	ti.Prompt = "❯ "
	ti.Placeholder = "filter: severity:high eco:go fixed, or free text"
	ti.CharLimit = 0
	styles := textinput.DefaultDarkStyles()
	styles.Focused.Prompt = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cYellow))
	styles.Focused.Placeholder = lipgloss.NewStyle().Foreground(lipgloss.Color(cGray))
	styles.Cursor.Color = lipgloss.Color(cOrange)
	styles.Cursor.Shape = tea.CursorBar
	ti.SetStyles(styles)
	focusCmd := ti.Focus()

	h := help.New()
	h.FullSeparator = "  "
	h.Styles = help.DefaultDarkStyles()
	h.Styles.ShortKey = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cYellow))
	h.Styles.ShortDesc = lipgloss.NewStyle().Foreground(lipgloss.Color(cGray))
	h.Styles.ShortSeparator = lipgloss.NewStyle().Faint(true).Foreground(lipgloss.Color(cGray))
	h.Styles.Ellipsis = lipgloss.NewStyle().Foreground(lipgloss.Color(cGray))

	m := Model{
		focusCmd:   focusCmd,
		cfg:        cfg,
		ctx:        ctx,
		input:      ti,
		preview:    viewport.New(),
		spin:       spinner.New(spinner.WithSpinner(spinner.Dot)),
		help:       h,
		status:     cfg.Notice,
		cachedAt:   cfg.CachedAt,
		previewFor: previewInvalid,
		width:      80,
		height:     24,
	}
	m.preview.MouseWheelEnabled = true
	m.setFindings(cfg.Findings)
	return m
}

func (m Model) now() time.Time {
	if m.cfg.Now != nil {
		return m.cfg.Now()
	}
	return time.Now()
}

func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.focusCmd}
	if m.cfg.ScanOnStart {
		cmds = append(cmds, func() tea.Msg { return startScanMsg{} })
	}
	return tea.Batch(cmds...)
}

type startScanMsg struct{}

func (m *Model) startScan() tea.Cmd {
	if m.scanning || m.cfg.Scan == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.scanning = true
	m.cancelScan = cancel
	scan := m.cfg.Scan
	return tea.Batch(m.spin.Tick, func() tea.Msg {
		defer cancel()
		fs, err := scan(ctx)
		return scanDoneMsg{findings: fs, err: err}
	})
}

// findingKey identifies a finding across rescans: the same OSV ID in the same
// package at the same lockfile.
type findingKey struct {
	id, ecosystem, name, version, source string
}

func keyOf(f model.Finding) findingKey {
	return findingKey{f.ID, f.Package.Ecosystem, f.Package.Name, f.Package.Version, f.Package.Source}
}

func (m *Model) setFindings(fs []model.Finding) {
	prevKey, hadPrev := m.selectedKey()
	m.sevCounts = [model.SeverityCritical + 1]int{}
	m.nameMaxW = 0
	m.verMaxW = 0
	m.idMaxW = 0
	m.findings = make([]model.Finding, len(fs))
	for i, f := range fs {
		m.findings[i] = model.SanitizeFinding(f)
	}
	model.SortFindings(m.findings)
	m.norm = make([]Normalized, len(m.findings))
	m.layouts = make([]keyLayout, len(m.findings))
	ecoSet := map[string]bool{}
	for i, f := range m.findings {
		m.norm[i], m.layouts[i] = Normalize(f)
		if f.Severity <= model.SeverityCritical {
			m.sevCounts[f.Severity]++
		}
		m.nameMaxW = max(m.nameMaxW, ansi.StringWidth(f.Package.Name))
		m.verMaxW = max(m.verMaxW, ansi.StringWidth(f.Package.Version))
		m.idMaxW = max(m.idMaxW, ansi.StringWidth(f.ID))
		if f.Package.Ecosystem != "" {
			ecoSet[f.Package.Ecosystem] = true
		}
	}
	prevEco := m.ecoName()
	m.ecos = m.ecos[:0]
	for e := range ecoSet {
		m.ecos = append(m.ecos, e)
	}
	slices.Sort(m.ecos)
	m.eco = 0
	if i := slices.Index(m.ecos, prevEco); i >= 0 {
		m.eco = i + 1
	}
	m.previewFor = previewInvalid
	keep := -1
	if hadPrev {
		keep = slices.IndexFunc(m.findings, func(f model.Finding) bool { return keyOf(f) == prevKey })
	}
	m.refreshKeep(keep)
}

func (m Model) ecoName() string {
	if m.eco <= 0 || m.eco > len(m.ecos) {
		return ""
	}
	return m.ecos[m.eco-1]
}

func (m Model) filter() Filter {
	return Filter{MinSeverity: m.sev.min(), Ecosystem: m.ecoName(), FixedOnly: m.fixedOnly}
}

// refresh recomputes the visible results and keeps the cursor in range.
func (m *Model) refresh() {
	var selected = -1
	if f, ok := m.selected(); ok {
		selected = f
	}
	m.refreshKeep(selected)
}

// refreshKeep recomputes the visible results. keep is the index into m.findings
// to keep selected when only filters or data changed; -1 selects the first row.
func (m *Model) refreshKeep(keep int) {
	// Passing the previous results reuses their capacity (no regrowth per keystroke).
	m.results, m.terms = Search(m.results, m.findings, m.norm, m.input.Value(), m.filter())
	m.cursor = 0
	if m.input.Value() == "" && keep >= 0 {
		// Keep the selection when only filters or data changed.
		for i, r := range m.results {
			if r.Index == keep {
				m.cursor = i
				break
			}
		}
	}
	m.clampOffset()
	m.updatePreview()
}

func (m Model) selected() (int, bool) {
	if m.cursor < 0 || m.cursor >= len(m.results) {
		return -1, false
	}
	return m.results[m.cursor].Index, true
}

func (m Model) selectedKey() (findingKey, bool) {
	i, ok := m.selected()
	if !ok {
		return findingKey{}, false
	}
	return keyOf(m.findings[i]), true
}

func (m *Model) moveCursor(delta int) {
	if len(m.results) == 0 {
		return
	}
	m.cursor = max(0, min(len(m.results)-1, m.cursor+delta))
	m.clampOffset()
	m.updatePreview()
}

func (m *Model) clampOffset() {
	h := m.listHeight()
	if h <= 0 {
		m.offset = 0
		return
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+h {
		m.offset = m.cursor - h + 1
	}
	m.offset = max(0, min(m.offset, max(0, len(m.results)-h)))
}

func (m *Model) updatePreview() {
	m.layout()
	idx, _ := m.selected()
	showErr := m.scanErr != nil
	w := m.preview.Width()
	if idx == m.previewFor && w == m.previewWidth && showErr == m.previewErr {
		return
	}
	scrollReset := idx != m.previewFor
	m.previewFor, m.previewWidth, m.previewErr = idx, w, showErr

	var b strings.Builder
	if showErr {
		b.WriteString(m.renderError(w))
		b.WriteString("\n\n")
	}
	if idx >= 0 {
		b.WriteString(m.renderDetail(m.findings[idx], w))
	}
	m.preview.SetContent(b.String())
	if scrollReset {
		m.preview.GotoTop()
	}
}
