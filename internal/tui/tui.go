// Package tui is the interactive terminal interface (bubbletea).
package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/engine"
	"github.com/Derposd/prosvet/internal/i18n"
	"github.com/Derposd/prosvet/internal/model"
	"github.com/Derposd/prosvet/internal/report"
	"github.com/Derposd/prosvet/internal/theme"
)

// Deps are the services the TUI needs.
type Deps struct {
	Bundle        *i18n.Bundle
	Catalog       *catalog.Catalog
	NewEngine     func() *engine.Engine
	DetectNetwork func(ctx context.Context) model.NetworkInfo
	NeedConsent   bool
	SaveConsent   func()
	SaveReport    func(*model.Report)
	LoadReport    func() (*model.Report, error)
	Demo          bool
	AutoStart     bool // start a full scan immediately
}

// Run starts the TUI and blocks until the user quits.
func Run(ctx context.Context, d Deps) error {
	p := tea.NewProgram(newModel(ctx, d), tea.WithAltScreen(), tea.WithContext(ctx))
	_, err := p.Run()
	if errors.Is(err, tea.ErrProgramKilled) {
		return nil
	}
	return err
}

type screen int

const (
	scrMenu screen = iota
	scrConsent
	scrCategories
	scrProgress
	scrResults
	scrWhitelist
	scrExport
)

type (
	netMsg   model.NetworkInfo
	eventMsg engine.Event
	doneMsg  struct {
		rep *model.Report
		err error
	}
	wlDoneMsg struct {
		res *model.WhitelistResult
		err error
	}
	exportedMsg struct {
		path string
		err  error
	}
)

type ui struct {
	ctx    context.Context
	d      Deps
	b      *i18n.Bundle
	w, h   int
	screen screen

	net     *model.NetworkInfo
	menu    int
	pending func() tea.Cmd // action waiting for consent

	cats     []*catalog.Category
	catSel   map[string]bool
	catIdx   int
	selected catalog.Selection

	spin   spinner.Model
	prog   progress.Model
	events chan engine.Event
	cancel context.CancelFunc
	phase  string
	done   int
	total  int
	recent []model.TargetResult
	wlMode bool
	status string

	rep      *model.Report
	view     *report.View
	items    []item
	cursor   int
	offset   int
	onlyBad  bool
	detailY  int
	wl       *model.WhitelistResult
	exportIx int
}

func newModel(ctx context.Context, d Deps) *ui {
	sp := spinner.New()
	sp.Spinner = spinner.MiniDot
	sp.Style = lipgloss.NewStyle().Foreground(theme.ColAccent)
	pr := progress.New(progress.WithGradient(theme.Accent, "#B9F2FF"), progress.WithoutPercentage())
	m := &ui{ctx: ctx, d: d, b: d.Bundle, spin: sp, prog: pr, catSel: map[string]bool{}}
	if d.Catalog != nil {
		for _, c := range d.Catalog.Categories {
			m.cats = append(m.cats, c)
			m.catSel[c.ID] = c.Default
		}
	}
	return m
}

func (m *ui) Init() tea.Cmd {
	cmds := []tea.Cmd{m.spin.Tick, m.detectNet()}
	if m.d.AutoStart {
		cmds = append(cmds, func() tea.Msg { return tea.KeyMsg{Type: tea.KeyEnter} })
	}
	return tea.Batch(cmds...)
}

func (m *ui) detectNet() tea.Cmd {
	if m.d.DetectNetwork == nil {
		return nil
	}
	return func() tea.Msg { return netMsg(m.d.DetectNetwork(m.ctx)) }
}

func waitEvent(ch <-chan engine.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return nil
		}
		return eventMsg(ev)
	}
}

func (m *ui) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.prog.Width = max(10, min(60, m.w-24))
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd
	case progress.FrameMsg:
		pm, cmd := m.prog.Update(msg)
		m.prog = pm.(progress.Model)
		return m, cmd
	case netMsg:
		n := model.NetworkInfo(msg)
		m.net = &n
		return m, nil
	case eventMsg:
		return m.onEvent(engine.Event(msg))
	case doneMsg:
		m.cancel = nil
		if msg.rep != nil {
			if m.d.SaveReport != nil {
				m.d.SaveReport(msg.rep)
			}
			m.showReport(msg.rep)
		} else {
			m.status = fmt.Sprint(msg.err)
			m.screen = scrMenu
		}
		return m, nil
	case wlDoneMsg:
		m.cancel = nil
		if msg.res != nil {
			m.wl = msg.res
			m.screen = scrWhitelist
		} else {
			m.status = fmt.Sprint(msg.err)
			m.screen = scrMenu
		}
		return m, nil
	case exportedMsg:
		if msg.err != nil {
			m.status = msg.err.Error()
		} else {
			m.status = m.b.T("ui.exported", "path", msg.path)
		}
		m.screen = scrResults
		return m, nil
	case tea.KeyMsg:
		return m.onKey(msg)
	}
	return m, nil
}

func (m *ui) onEvent(ev engine.Event) (tea.Model, tea.Cmd) {
	switch ev.Kind {
	case engine.EventStarted:
		m.total = ev.Total
	case engine.EventPhase:
		m.phase = ev.Phase
		if ev.Total > 0 {
			m.total = ev.Total
		}
		if m.wlMode {
			m.done = ev.Done
		}
	case engine.EventTarget:
		m.done = ev.Done
		if ev.Target != nil && ev.Target.Role != "baseline" {
			m.recent = append(m.recent, *ev.Target)
		}
	}
	var cmd tea.Cmd
	if m.total > 0 {
		cmd = m.prog.SetPercent(float64(m.done) / float64(m.total))
	}
	return m, tea.Batch(cmd, waitEvent(m.events))
}

func (m *ui) quit() (tea.Model, tea.Cmd) {
	if m.cancel != nil {
		m.cancel()
	}
	return m, tea.Quit
}

func (m *ui) onKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := k.String()
	if key == "ctrl+c" {
		return m.quit()
	}
	switch m.screen {
	case scrMenu:
		return m.keyMenu(key)
	case scrConsent:
		switch key {
		case "y", "Y", "д", "enter":
			if m.d.SaveConsent != nil {
				m.d.SaveConsent()
			}
			m.d.NeedConsent = false
			if m.pending != nil {
				return m, m.pending()
			}
			m.screen = scrMenu
		case "n", "N", "esc", "q":
			m.screen = scrMenu
		}
	case scrCategories:
		return m.keyCategories(key)
	case scrProgress:
		if key == "esc" && m.cancel != nil {
			m.cancel()
			m.status = m.b.T("ui.cancelled")
		}
	case scrResults:
		return m.keyResults(key)
	case scrWhitelist:
		switch key {
		case "q":
			return m.quit()
		case "esc", "enter":
			if m.rep != nil {
				m.screen = scrResults
			} else {
				m.screen = scrMenu
			}
		}
	case scrExport:
		switch key {
		case "up", "k":
			m.exportIx = (m.exportIx + 2) % 3
		case "down", "j":
			m.exportIx = (m.exportIx + 1) % 3
		case "enter":
			return m, m.export([]string{"html", "md", "json"}[m.exportIx])
		case "esc", "q":
			m.screen = scrResults
		}
	}
	return m, nil
}

const menuItems = 5

func (m *ui) keyMenu(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q", "esc":
		return m.quit()
	case "up", "k":
		m.menu = (m.menu + menuItems - 1) % menuItems
	case "down", "j":
		m.menu = (m.menu + 1) % menuItems
	case "enter", " ":
		m.status = ""
		switch m.menu {
		case 0:
			return m, m.withConsent(func() tea.Cmd { return m.startScan(catalog.Selection{}) })
		case 1:
			m.screen = scrCategories
		case 2:
			return m, m.withConsent(m.startWhitelist)
		case 3:
			if m.d.LoadReport != nil {
				if rep, err := m.d.LoadReport(); err == nil {
					m.showReport(rep)
					return m, nil
				}
			}
			m.status = m.b.T("ui.no_report")
		case 4:
			return m.quit()
		}
	}
	return m, nil
}

func (m *ui) withConsent(action func() tea.Cmd) tea.Cmd {
	if m.d.NeedConsent {
		m.pending = action
		m.screen = scrConsent
		return nil
	}
	return action()
}

func (m *ui) keyCategories(key string) (tea.Model, tea.Cmd) {
	n := len(m.cats)
	switch key {
	case "esc", "q":
		m.screen = scrMenu
	case "up", "k":
		if n > 0 {
			m.catIdx = (m.catIdx + n - 1) % n
		}
	case "down", "j":
		if n > 0 {
			m.catIdx = (m.catIdx + 1) % n
		}
	case " ", "x":
		if n > 0 {
			id := m.cats[m.catIdx].ID
			m.catSel[id] = !m.catSel[id]
		}
	case "enter":
		var sel catalog.Selection
		for _, c := range m.cats {
			if m.catSel[c.ID] {
				sel.Categories = append(sel.Categories, c.ID)
			}
		}
		if len(sel.Categories) == 0 {
			return m, nil
		}
		return m, m.withConsent(func() tea.Cmd { return m.startScan(sel) })
	}
	return m, nil
}

func (m *ui) startScan(sel catalog.Selection) tea.Cmd {
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel = cancel
	m.selected = sel
	m.events = make(chan engine.Event, 64)
	m.screen, m.wlMode = scrProgress, false
	m.done, m.total, m.phase, m.recent = 0, 0, "", nil
	eng := m.d.NewEngine()
	net := model.NetworkInfo{Conn: "unknown"}
	if m.net != nil {
		net = *m.net
	}
	events := m.events
	run := func() tea.Msg {
		rep, err := eng.Scan(ctx, sel, net, events)
		close(events)
		return doneMsg{rep: rep, err: err}
	}
	return tea.Batch(run, waitEvent(events), m.prog.SetPercent(0))
}

func (m *ui) startWhitelist() tea.Cmd {
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel = cancel
	m.events = make(chan engine.Event, 64)
	m.screen, m.wlMode = scrProgress, true
	m.done, m.total, m.phase, m.recent = 0, 0, engine.PhaseWL, nil
	eng := m.d.NewEngine()
	events := m.events
	run := func() tea.Msg {
		res, err := eng.Whitelist(ctx, events)
		close(events)
		return wlDoneMsg{res: res, err: err}
	}
	return tea.Batch(run, waitEvent(events), m.prog.SetPercent(0))
}

func (m *ui) export(format string) tea.Cmd {
	rep, view := m.rep, m.view
	return func() tea.Msg {
		name := fmt.Sprintf("prosvet-report-%s.%s", time.Now().Format("20060102-1504"), format)
		f, err := os.Create(name)
		if err != nil {
			return exportedMsg{err: err}
		}
		defer f.Close()
		switch format {
		case "html":
			err = report.WriteHTML(f, view)
		case "md":
			err = report.WriteMarkdown(f, view)
		default:
			err = report.WriteJSON(f, rep)
		}
		abs, _ := filepath.Abs(name)
		return exportedMsg{path: abs, err: err}
	}
}

func (m *ui) showReport(rep *model.Report) {
	m.rep = rep
	titles := report.CategoryTitles{}
	if m.d.Catalog != nil {
		for _, c := range m.d.Catalog.Categories {
			titles[c.ID] = c.Title.Get(m.b.Lang)
		}
	}
	m.view = report.Build(rep, m.b, titles)
	if rep.Whitelist != nil && len(rep.Targets) == 0 {
		m.wl = rep.Whitelist
		m.screen = scrWhitelist
		return
	}
	m.buildItems()
	m.cursor, m.offset, m.detailY = m.firstSelectable(), 0, 0
	m.screen = scrResults
}

// View renders the current screen.
func (m *ui) View() string {
	if m.w == 0 {
		return ""
	}
	var body string
	switch m.screen {
	case scrMenu:
		body = m.viewMenu()
	case scrConsent:
		body = m.viewConsent()
	case scrCategories:
		body = m.viewCategories()
	case scrProgress:
		body = m.viewProgress()
	case scrResults:
		body = m.viewResults()
	case scrWhitelist:
		body = m.viewWhitelist()
	case scrExport:
		body = m.viewExport()
	}
	return lipgloss.NewStyle().MaxWidth(m.w).MaxHeight(m.h).Render(body)
}

func (m *ui) header() string {
	left := theme.Title.Render("◤ Prosvet") + theme.Dim.Render("  "+m.b.T("app.tagline"))
	var right string
	switch {
	case m.d.Demo:
		right = theme.Warn.Render(m.b.T("app.demo_banner"))
	case m.net == nil:
		right = theme.Dim.Render(m.spin.View() + " " + m.b.T("ui.detecting"))
	default:
		right = theme.Dim.Render(networkLine(m.net, m.b))
	}
	gap := m.w - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		return " " + left + "\n " + right
	}
	return " " + left + strings.Repeat(" ", gap) + right
}

func networkLine(n *model.NetworkInfo, b *i18n.Bundle) string {
	parts := []string{}
	if n.ISP != "" {
		s := n.ISP
		if n.ASN != 0 {
			s += fmt.Sprintf(" (AS%d)", n.ASN)
		}
		parts = append(parts, s)
	}
	if n.RegionName != "" {
		parts = append(parts, n.RegionName)
	}
	parts = append(parts, b.T("conn."+n.Conn))
	s := strings.Join(parts, " · ")
	if n.VPNSuspected {
		s = "⚠ VPN · " + s
	}
	return s
}

func (m *ui) footer(keys string) string {
	line := theme.Dim.Render(" " + keys)
	if m.status != "" {
		line = theme.Warn.Render(" "+m.status) + "\n" + line
	}
	return line
}

func (m *ui) frame(content, keys string) string {
	head := m.header()
	foot := m.footer(keys)
	avail := m.h - lipgloss.Height(head) - lipgloss.Height(foot) - 1
	content = lipgloss.NewStyle().Height(max(avail, 1)).MaxHeight(max(avail, 1)).Render(content)
	return head + "\n" + content + "\n" + foot
}

func (m *ui) viewMenu() string {
	labels := [][2]string{
		{m.b.T("ui.menu.scan"), m.b.T("ui.menu.scan_hint")},
		{m.b.T("ui.menu.categories"), m.b.T("ui.menu.categories_hint")},
		{m.b.T("ui.menu.whitelist"), m.b.T("ui.menu.whitelist_hint")},
		{m.b.T("ui.menu.last"), m.b.T("ui.menu.last_hint")},
		{m.b.T("ui.menu.quit"), ""},
	}
	var sb strings.Builder
	sb.WriteString("\n" + logoBlock() + "\n\n")
	for i, l := range labels {
		cursor := "  "
		style := lipgloss.NewStyle()
		if i == m.menu {
			cursor = theme.Title.Render("▸ ")
			style = style.Bold(true).Foreground(theme.ColAccent)
		}
		line := "   " + cursor + style.Render(l[0])
		if l[1] != "" {
			line += theme.Dim.Render("  — " + l[1])
		}
		sb.WriteString(line + "\n")
	}
	return m.frame(sb.String(), m.b.T("ui.menu_keys"))
}

func logoBlock() string {
	ray := lipgloss.NewStyle().Foreground(theme.ColAccent)
	wall := lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Dark: theme.Text, Light: "#1F2328"})
	l1 := "   " + wall.Render("█") + "\n"
	l2 := ray.Render("╶──") + wall.Render(" ") + ray.Render("━━━━━▶") + "  " + theme.Title.Render("P R O S V E T") + "\n"
	l3 := "   " + wall.Render("█")
	return lipgloss.NewStyle().PaddingLeft(4).Render(l1 + l2 + l3)
}

func (m *ui) viewConsent() string {
	box := theme.Box.Width(min(72, m.w-6)).Render(
		theme.Bold.Render(m.b.T("ui.consent_title")) + "\n\n" +
			strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(m.b.T("cli.consent"), "[y/N] ")), "?") + "?")
	return m.frame("\n"+lipgloss.NewStyle().PaddingLeft(3).Render(box), m.b.T("ui.consent_keys"))
}

func (m *ui) viewCategories() string {
	var sb strings.Builder
	sb.WriteString("\n   " + theme.Bold.Render(m.b.T("ui.categories_title")) + "\n\n")
	for i, c := range m.cats {
		box := "[ ]"
		if m.catSel[c.ID] {
			box = theme.Title.Render("[x]")
		}
		cursor := "  "
		if i == m.catIdx {
			cursor = theme.Title.Render("▸ ")
		}
		line := fmt.Sprintf("   %s%s %s", cursor, box, c.Title.Get(m.b.Lang))
		if len(c.Consent) > 0 {
			line += theme.Warn.Render("  (" + m.b.T("ui.opt_in") + ")")
		}
		line += theme.Dim.Render(fmt.Sprintf("  %d", len(c.Targets)))
		sb.WriteString(line + "\n")
	}
	return m.frame(sb.String(), m.b.T("ui.categories_keys"))
}

func (m *ui) viewProgress() string {
	var sb strings.Builder
	phase := m.b.T("cli.phase." + m.phase)
	if m.phase == "" {
		phase = m.b.T("ui.scanning") + "…"
	}
	sb.WriteString("\n   " + m.spin.View() + " " + theme.Bold.Render(phase) + "\n\n")
	sb.WriteString("   " + m.prog.View() + theme.Dim.Render(fmt.Sprintf("  %d/%d", m.done, m.total)) + "\n\n")
	rows := m.h - 12
	start := max(0, len(m.recent)-rows)
	for _, t := range m.recent[start:] {
		line := fmt.Sprintf("   %s %-24s %s", theme.Dot(t.Status), trunc(t.Name, 24), theme.StatusLabel(t.Status, m.b.Status(t.Status)))
		if t.Status != model.StatusOK {
			line += theme.Dim.Render("  " + m.b.KindTitle(t.Verdict.Kind))
		}
		sb.WriteString(line + "\n")
	}
	return m.frame(sb.String(), m.b.T("ui.progress_keys"))
}

func (m *ui) viewWhitelist() string {
	if m.wl == nil {
		return m.frame("", m.b.T("ui.wl_keys"))
	}
	v := report.BuildWhitelist(m.wl, m.b)
	st := report.WhitelistStatus(v.Verdict)
	width := min(84, m.w-6)
	var sb strings.Builder
	sb.WriteString(theme.Dot(st) + " " + theme.StatusLabel(st, v.Title) + "\n\n")
	sb.WriteString(lipgloss.NewStyle().Width(width - 4).Render(v.Explain))
	sb.WriteString("\n\n" + theme.Dim.Render(v.Counts))
	if v.Level != "" {
		sb.WriteString("\n" + theme.Dim.Render("→ "+v.Level))
	}
	col := func(title string, hs []report.WLHostView) string {
		var c strings.Builder
		c.WriteString(theme.Bold.Render(title) + "\n")
		for _, h := range hs {
			s := model.StatusOK
			if !h.OK {
				s = model.StatusBlocked
			}
			c.WriteString(theme.Dot(s) + " " + trunc(h.Host, 26) + "\n")
		}
		return c.String()
	}
	cols := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(width/2).Render(col(m.b.T("whitelist.domestic"), v.Domestic)),
		col(m.b.T("whitelist.foreign"), v.Foreign))
	box := theme.Box.Width(width).Render(sb.String() + "\n\n" + cols)
	return m.frame("\n"+lipgloss.NewStyle().PaddingLeft(2).Render(box), m.b.T("ui.wl_keys"))
}

func (m *ui) viewExport() string {
	opts := []string{"HTML", "Markdown", "JSON"}
	var sb strings.Builder
	sb.WriteString("\n   " + theme.Bold.Render(m.b.T("ui.export_title")) + "\n\n")
	for i, o := range opts {
		cursor := "  "
		if i == m.exportIx {
			cursor = theme.Title.Render("▸ ")
		}
		sb.WriteString("   " + cursor + o + "\n")
	}
	return m.frame(sb.String(), m.b.T("ui.export_keys"))
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
