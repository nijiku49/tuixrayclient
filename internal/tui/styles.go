package tui

import "github.com/charmbracelet/lipgloss"

var (
	colAccent = lipgloss.AdaptiveColor{Light: "#0E7C86", Dark: "#3DD6C6"}
	colOK     = lipgloss.AdaptiveColor{Light: "#1B8A3A", Dark: "#5FD787"}
	colWarn   = lipgloss.AdaptiveColor{Light: "#A66B00", Dark: "#F2C45A"}
	colBad    = lipgloss.AdaptiveColor{Light: "#C62828", Dark: "#FF6B6B"}
	colDim    = lipgloss.AdaptiveColor{Light: "#7A7A7A", Dark: "#6C7086"}
	colText   = lipgloss.AdaptiveColor{Light: "#1F1F1F", Dark: "#E6E6E6"}
	colSelBg  = lipgloss.AdaptiveColor{Light: "#D9F2EF", Dark: "#23363A"}
	colBorder = lipgloss.AdaptiveColor{Light: "#C8C8C8", Dark: "#3A3F4B"}

	sTitle    = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	sTabOn    = lipgloss.NewStyle().Bold(true).Foreground(colText).Underline(true)
	sTabOff   = lipgloss.NewStyle().Foreground(colDim)
	sDim      = lipgloss.NewStyle().Foreground(colDim)
	sText     = lipgloss.NewStyle().Foreground(colText)
	sOK       = lipgloss.NewStyle().Foreground(colOK)
	sWarn     = lipgloss.NewStyle().Foreground(colWarn)
	sBad      = lipgloss.NewStyle().Foreground(colBad)
	sBold     = lipgloss.NewStyle().Bold(true)
	sGroup    = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	sSel      = lipgloss.NewStyle().Background(colSelBg)
	sKey      = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	sRule     = lipgloss.NewStyle().Foreground(colBorder)
	sBox      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colAccent).Padding(1, 3)
	sErrBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colBad).Padding(0, 2)
	sProto    = lipgloss.NewStyle().Foreground(colDim)
	sCurrent  = lipgloss.NewStyle().Foreground(colOK).Bold(true)
	sAnnounce = lipgloss.NewStyle().Foreground(colWarn)
)

func pingStyle(ms int) lipgloss.Style {
	switch {
	case ms < 0:
		return sBad
	case ms == 0:
		return sDim
	case ms < 200:
		return sOK
	case ms < 500:
		return sWarn
	}
	return sBad
}
