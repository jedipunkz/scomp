// Styles. Text colors follow the gruvbox (dark) palette; the terminal's
// background is left untouched.
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

	// list columns
	stylePackage    = lipgloss.NewStyle().Foreground(lipgloss.Color(cBlue))
	stylePackageSel = stylePackage.Bold(true)
	styleVersion    = lipgloss.NewStyle().Foreground(lipgloss.Color(cAqua))
	styleVersionSel = styleVersion.Bold(true)
	styleID         = lipgloss.NewStyle().Foreground(lipgloss.Color(cPurple))
	styleIDSel      = styleID.Bold(true)
	styleSummary    = lipgloss.NewStyle().Foreground(lipgloss.Color(cGray))

	// detail pane
	styleDetailID  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cYellow))
	styleDetailAlt = lipgloss.NewStyle().Foreground(lipgloss.Color(cOrange)) // CVE / alias IDs
	styleFixed     = lipgloss.NewStyle().Foreground(lipgloss.Color(cGreen))
	styleURL       = lipgloss.NewStyle().Foreground(lipgloss.Color(cBlue))

	severityStyles = map[model.Severity]lipgloss.Style{
		model.SeverityCritical: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color(cRed)),
		model.SeverityHigh:     lipgloss.NewStyle().Foreground(lipgloss.Color(cRed)),
		model.SeverityMedium:   lipgloss.NewStyle().Foreground(lipgloss.Color(cYellow)),
		model.SeverityLow:      lipgloss.NewStyle().Foreground(lipgloss.Color(cGreen)),
		model.SeverityUnknown:  lipgloss.NewStyle().Foreground(lipgloss.Color(cGray)),
	}
)
