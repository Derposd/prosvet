package tui

import (
	"context"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/Derposd/prosvet/internal/catalog"
	"github.com/Derposd/prosvet/internal/demo"
	"github.com/Derposd/prosvet/internal/engine"
	"github.com/Derposd/prosvet/internal/i18n"
	"github.com/Derposd/prosvet/internal/model"
)

func sampleReport() *model.Report {
	return &model.Report{
		Schema:  model.ReportSchema,
		Network: model.NetworkInfo{ASN: 64500, ISP: "Demo Telecom", Conn: "fixed"},
		Targets: []model.TargetResult{
			{ID: "a", Name: "Alpha", Category: "c1", Status: model.StatusBlocked,
				Verdict:   model.Verdict{Kind: model.KindSNIDPI, Confidence: model.High, Evidence: []model.Evidence{{Key: "ev.runs", Args: map[string]string{"agree": "3", "runs": "3"}}}},
				Endpoints: []model.EndpointResult{{Name: "alpha.example", Verdict: model.Verdict{Kind: model.KindSNIDPI}}}},
			{ID: "b", Name: "Beta", Category: "c1", Status: model.StatusOK, Verdict: model.Verdict{Kind: model.KindOK, Confidence: model.High}},
			{ID: "c", Name: "Gamma", Category: "c2", Status: model.StatusThrottled, Verdict: model.Verdict{Kind: model.KindThrottleFreeze, Confidence: model.High}},
		},
		Summary: model.Summary{Total: 3, OK: 1, Throttled: 1, Blocked: 1},
	}
}

func press(m *ui, keys ...string) {
	for _, k := range keys {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		case "down":
			msg = tea.KeyMsg{Type: tea.KeyDown}
		case "up":
			msg = tea.KeyMsg{Type: tea.KeyUp}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		m.Update(msg)
	}
}

func TestResultsNavigationAndFilter(t *testing.T) {
	m := newModel(context.Background(), Deps{Bundle: i18n.New("en"), LoadReport: func() (*model.Report, error) { return sampleReport(), nil }})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	press(m, "down", "down", "down", "enter") // "Last report"
	if m.screen != scrResults {
		t.Fatalf("screen %v", m.screen)
	}
	out := m.View()
	for _, want := range []string{"Alpha", "Beta", "Gamma", "DPI blocking by server name"} {
		if !strings.Contains(out, want) {
			t.Fatalf("view lacks %q:\n%s", want, out)
		}
	}
	press(m, "f")
	if strings.Contains(m.View(), "Beta") {
		t.Fatal("filter must hide working targets")
	}
	press(m, "down")
	if !strings.Contains(m.View(), "Throttling: transfer freezes") {
		t.Fatal("detail pane must follow the cursor")
	}
	press(m, "e")
	if m.screen != scrExport {
		t.Fatal("e must open export")
	}
	press(m, "esc", "esc")
	if m.screen != scrMenu {
		t.Fatalf("esc must return to the menu, got %v", m.screen)
	}
}

func TestConsentGate(t *testing.T) {
	m := newModel(context.Background(), Deps{Bundle: i18n.New("ru"), NeedConsent: true,
		Catalog: &catalog.Catalog{}, NewEngine: func() *engine.Engine { return nil }})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	press(m, "enter")
	if m.screen != scrConsent {
		t.Fatalf("scan must ask for consent first, got %v", m.screen)
	}
	press(m, "n")
	if m.screen != scrMenu {
		t.Fatal("declining must return to the menu")
	}
}

func TestDemoScanEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	env, err := demo.Start("test")
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	var saved *model.Report
	m := newModel(context.Background(), Deps{
		Bundle: i18n.New("en"), Catalog: env.Catalog, Demo: true,
		NewEngine:  func() *engine.Engine { return env.Engine },
		SaveReport: func(r *model.Report) { saved = r },
	})
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m.net = &demo.Network
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != scrProgress {
		t.Fatalf("screen %v", m.screen)
	}
	// Drive the command loop manually until the scan finishes.
	deadline := time.Now().Add(60 * time.Second)
	queue := []tea.Cmd{cmd}
	for len(queue) > 0 && m.screen == scrProgress && time.Now().Before(deadline) {
		c := queue[0]
		queue = queue[1:]
		if c == nil {
			continue
		}
		msg := c()
		if batch, ok := msg.(tea.BatchMsg); ok {
			queue = append(queue, batch...)
			continue
		}
		if msg == nil {
			continue
		}
		if _, next := m.Update(msg); next != nil {
			queue = append(queue, next)
		}
	}
	if m.screen != scrResults || saved == nil {
		t.Fatalf("scan did not finish: screen %v saved %v", m.screen, saved != nil)
	}
	if !strings.Contains(m.View(), "Messenger A") {
		t.Fatal("results must list demo targets")
	}
}
