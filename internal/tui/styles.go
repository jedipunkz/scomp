// Styles. Text colors follow the gruvbox (dark) palette; the terminal's
// background is left untouched and no background colors are set on text.
package tui

import (
	"charm.land/lipgloss/v2"

	"github.com/jedipunkz/scomp/internal/model"
)

// gruvbox dark palette.
const (
	cFg     = "#ebdbb2"
	cGray   = "#928374"
	cRed    = "#fb4934"
	cGreen  = "#b8bb26"
	cYellow = "#fabd2f"
	cBlue   = "#83a598"
	cPurple = "#d3869b"
	cAqua   = "#8ec07c"
	cOrange = "#fe8019"
)

var (
	// shared
	styleTitle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cYellow))
	styleDim       = lipgloss.NewStyle().Faint(true).Foreground(lipgloss.Color(cGray))
	styleBold      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cFg))
	styleHighlight = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cYellow))
	styleError     = lipgloss.NewStyle().Foreground(lipgloss.Color(cRed))
	styleMarker    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cOrange))

	// pane title bars
	stylePaneLabel = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cYellow))
	styleRule      = lipgloss.NewStyle().Foreground(lipgloss.Color(cGray))

	// list columns
	stylePackage    = lipgloss.NewStyle().Foreground(lipgloss.Color(cBlue))
	stylePackageSel = stylePackage.Bold(true)
	styleVersion    = lipgloss.NewStyle().Foreground(lipgloss.Color(cAqua))
	styleVersionSel = styleVersion.Bold(true)
	styleID         = lipgloss.NewStyle().Foreground(lipgloss.Color(cPurple))
	styleIDSel      = styleID.Bold(true)
	styleSummary    = lipgloss.NewStyle().Foreground(lipgloss.Color(cGray))
	styleSummarySel = styleSummary.Bold(true)

	// detail pane
	styleDetailID  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cYellow))
	styleDetailAlt = lipgloss.NewStyle().Foreground(lipgloss.Color(cOrange)) // CVE / alias IDs
	styleFixed     = lipgloss.NewStyle().Foreground(lipgloss.Color(cGreen))
	styleURL       = lipgloss.NewStyle().Foreground(lipgloss.Color(cBlue))

	// GitHub issue popup
	styleModalBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color(cGray)).
			Padding(1, 2)

	severityStyles = map[model.Severity]lipgloss.Style{
		model.SeverityCritical: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cRed)),
		model.SeverityHigh:     lipgloss.NewStyle().Foreground(lipgloss.Color(cRed)),
		model.SeverityMedium:   lipgloss.NewStyle().Foreground(lipgloss.Color(cYellow)),
		model.SeverityLow:      lipgloss.NewStyle().Foreground(lipgloss.Color(cGreen)),
		model.SeverityUnknown:  lipgloss.NewStyle().Foreground(lipgloss.Color(cGray)),
	}
)
