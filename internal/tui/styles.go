package tui

import (
	"charm.land/lipgloss/v2"

	"github.com/jedipunkz/scomp/internal/model"
)

var (
	styleTitle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	styleDim       = lipgloss.NewStyle().Faint(true)
	styleBold      = lipgloss.NewStyle().Bold(true)
	styleSelected  = lipgloss.NewStyle().Bold(true)
	styleHighlight = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("3"))
	styleError     = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styleMarker    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))

	severityStyles = map[model.Severity]lipgloss.Style{
		model.SeverityCritical: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")),
		model.SeverityHigh:     lipgloss.NewStyle().Foreground(lipgloss.Color("1")),
		model.SeverityMedium:   lipgloss.NewStyle().Foreground(lipgloss.Color("3")),
		model.SeverityLow:      lipgloss.NewStyle().Foreground(lipgloss.Color("2")),
		model.SeverityUnknown:  lipgloss.NewStyle().Faint(true),
	}
)
