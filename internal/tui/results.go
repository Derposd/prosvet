package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/ordinarysim/prosvet/internal/model"
	"github.com/ordinarysim/prosvet/internal/report"
	"github.com/ordinarysim/prosvet/internal/theme"
)

// item is a row of the results list: a category header or a target.
type item struct {
	header string
	target *report.TargetView
}

func (m *ui) buildItems() {
	m.items = nil
	for gi := range m.view.Groups {
		g := &m.view.Groups[gi]
		var rows []item
		for ti := range g.Targets {
			t := &g.Targets[ti]
			if m.onlyBad && t.Status == model.StatusOK {
				continue
			}
			rows = append(rows, item{target: t})
		}
		if len(rows) == 0 {
			continue
		}
		m.items = append(m.items, item{header: g.Title})
		m.items = append(m.items, rows...)
	}
}

func (m *ui) firstSelectable() int {
	for i, it := range m.items {
		if it.target != nil {
			return i
		}
	}
	return 0
}

func (m *ui) move(delta int) {
	i := m.cursor
	for {
		i += delta
		if i < 0 || i >= len(m.items) {
			return
		}
		if m.items[i].target != nil {
			m.cursor = i
			m.detailY = 0
			return
		}
	}
}

func (m *ui) keyResults(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return m.quit()
	case "esc":
		m.screen = scrMenu
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgdown", "ctrl+d":
		m.detailY += 5
	case "pgup", "ctrl+u":
		m.detailY = max(0, m.detailY-5)
	case "home", "g":
		m.cursor, m.offset = m.firstSelectable(), 0
	case "f":
		m.onlyBad = !m.onlyBad
		m.buildItems()
		m.cursor, m.offset = m.firstSelectable(), 0
	case "e":
		m.status = ""
		m.screen = scrExport
	case "w":
		return m, m.withConsent(m.startWhitelist)
	case "r":
		return m, m.withConsent(func() tea.Cmd { return m.startScan(m.selected) })
	}
	return m, nil
}

func (m *ui) viewResults() string {
	if m.view == nil {
		return m.frame("", m.b.T("ui.results_keys"))
	}
	head := m.summaryLine()
	avail := m.h - 5
	listW := min(40, max(28, m.w*36/100))
	detailW := m.w - listW - 3

	// Keep the cursor visible.
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+avail-1 {
		m.offset = m.cursor - avail + 2
	}
	if m.offset > 0 && m.offset < len(m.items) && m.items[m.offset].target != nil && m.items[m.offset-1].header != "" {
		m.offset--
	}
	var list strings.Builder
	for i := m.offset; i < len(m.items) && i < m.offset+avail-1; i++ {
		it := m.items[i]
		if it.header != "" {
			list.WriteString(theme.Heading.Render(trunc(strings.ToUpper(it.header), listW-2)) + "\n")
			continue
		}
		t := it.target
		name := trunc(t.Name, listW-6)
		line := " " + theme.Dot(t.Status) + " " + name
		if i == m.cursor {
			line = lipgloss.NewStyle().Background(lipgloss.AdaptiveColor{Dark: theme.Surface, Light: "#EAEEF2"}).
				Bold(true).Width(listW).Render(" " + theme.Dot(t.Status) + " " + name)
		}
		list.WriteString(line + "\n")
	}
	left := lipgloss.NewStyle().Width(listW).Height(avail).Render(list.String())
	sep := lipgloss.NewStyle().Foreground(theme.ColBorder).Render(strings.Repeat("│\n", max(avail-1, 1)) + "│")
	right := m.detail(detailW, avail)
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", sep, " ", right)
	keys := m.b.T("ui.results_keys")
	if m.onlyBad {
		keys = m.b.T("ui.filter_on") + " · " + keys
	}
	return m.header() + "\n" + head + "\n" + body + "\n" + m.footer(keys)
}

func (m *ui) summaryLine() string {
	var parts []string
	for _, c := range m.view.Counts {
		parts = append(parts, theme.Dot(c.Status)+" "+theme.StatusLabel(c.Status, fmt.Sprintf("%d", c.N))+" "+theme.Dim.Render(c.Word))
	}
	return " " + strings.Join(parts, "   ")
}

func (m *ui) detail(width, height int) string {
	if m.cursor >= len(m.items) || m.items[m.cursor].target == nil {
		return ""
	}
	t := m.items[m.cursor].target
	wrap := lipgloss.NewStyle().Width(width)
	var sb strings.Builder
	sb.WriteString(theme.Bold.Render(t.Name) + "  " + theme.StatusLabel(t.Status, t.StatusText) + "\n")
	if t.Status != model.StatusOK || t.Kind != model.KindOK {
		title := t.KindTitle
		if t.Subtype != "" {
			title += " — " + t.Subtype
		}
		sb.WriteString(wrap.Render(theme.Title.Render(title)+theme.Dim.Render(" · "+t.Confidence)) + "\n")
	}
	sb.WriteString("\n" + theme.Dim.Render(m.b.T("ui.why")) + "\n")
	sb.WriteString(wrap.Render(t.Explain) + "\n")
	if len(t.Evidence) > 0 {
		sb.WriteString("\n" + theme.Dim.Render(m.b.T("ui.evidence")) + "\n")
		for _, e := range t.Evidence {
			sb.WriteString(wrap.Render("• "+e) + "\n")
		}
	}
	if len(t.Secondary) > 0 {
		sb.WriteString("\n" + theme.Dim.Render(m.b.T("report.secondary")+": ") + strings.Join(t.Secondary, ", ") + "\n")
	}
	if len(t.Endpoints) > 0 {
		sb.WriteString("\n" + theme.Dim.Render(m.b.T("ui.endpoints")) + "\n")
		for _, e := range t.Endpoints {
			label := e.KindTitle
			if e.Subtype != "" {
				label += " — " + e.Subtype
			}
			sb.WriteString(wrap.Render(theme.Dot(report.KindStatus(e.Kind))+" "+e.Name+theme.Dim.Render("  "+label)) + "\n")
		}
	}
	if t.Expect != "" {
		sb.WriteString("\n" + theme.Dim.Render(t.Expect) + "\n")
	}
	lines := strings.Split(sb.String(), "\n")
	if m.detailY >= len(lines) {
		m.detailY = max(0, len(lines)-1)
	}
	lines = lines[m.detailY:]
	if len(lines) > height {
		lines = lines[:height]
	}
	return strings.Join(lines, "\n")
}
