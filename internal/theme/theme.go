// Package theme holds the shared colour palette for the terminal UI, the
// HTML report, the dashboard and the public map, so they look like one product.
package theme

import (
	"github.com/charmbracelet/lipgloss"

	"github.com/ordinarysim/prosvet/internal/model"
)

// Hex colours (dark-first palette; light variants for light terminals).
const (
	Accent     = "#7C9CFF"
	AccentDim  = "#4C5FA8"
	OK         = "#3FB950"
	Throttled  = "#D29922"
	Partial    = "#F0883E"
	Blocked    = "#F85149"
	Unknown    = "#8B949E"
	Text       = "#E6EDF3"
	Muted      = "#8B949E"
	Background = "#0D1117"
	Surface    = "#161B22"
	Border     = "#30363D"
)

func adaptive(dark, light string) lipgloss.AdaptiveColor {
	return lipgloss.AdaptiveColor{Dark: dark, Light: light}
}

// Terminal styles.
var (
	ColAccent    = adaptive(Accent, "#3451C7")
	ColOK        = adaptive(OK, "#1A7F37")
	ColThrottled = adaptive(Throttled, "#9A6700")
	ColPartial   = adaptive(Partial, "#BC4C00")
	ColBlocked   = adaptive(Blocked, "#CF222E")
	ColMuted     = adaptive(Muted, "#57606A")
	ColBorder    = adaptive(Border, "#D0D7DE")

	Title   = lipgloss.NewStyle().Bold(true).Foreground(ColAccent)
	Dim     = lipgloss.NewStyle().Foreground(ColMuted)
	Bold    = lipgloss.NewStyle().Bold(true)
	Heading = lipgloss.NewStyle().Bold(true).Foreground(ColAccent)
	Warn    = lipgloss.NewStyle().Foreground(ColThrottled)
	Box     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ColBorder).Padding(0, 1)
)

// StatusColor returns the colour for a target status.
func StatusColor(s model.Status) lipgloss.AdaptiveColor {
	switch s {
	case model.StatusOK:
		return ColOK
	case model.StatusThrottled:
		return ColThrottled
	case model.StatusPartial:
		return ColPartial
	case model.StatusBlocked:
		return ColBlocked
	default:
		return ColMuted
	}
}

// StatusHex returns the hex colour for a target status (HTML outputs).
func StatusHex(s model.Status) string {
	switch s {
	case model.StatusOK:
		return OK
	case model.StatusThrottled:
		return Throttled
	case model.StatusPartial:
		return Partial
	case model.StatusBlocked:
		return Blocked
	default:
		return Unknown
	}
}

// Dot returns a coloured status bullet.
func Dot(s model.Status) string {
	return lipgloss.NewStyle().Foreground(StatusColor(s)).Render("●")
}

// StatusLabel renders a coloured status label.
func StatusLabel(s model.Status, text string) string {
	return lipgloss.NewStyle().Foreground(StatusColor(s)).Bold(s != model.StatusOK).Render(text)
}
