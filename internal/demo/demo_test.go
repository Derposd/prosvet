package demo

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/ordinarysim/prosvet/internal/catalog"
	"github.com/ordinarysim/prosvet/internal/i18n"
	"github.com/ordinarysim/prosvet/internal/model"
	"github.com/ordinarysim/prosvet/internal/report"
)

func TestDemoShowsEveryMajorVerdict(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	env, err := Start("test")
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	rep, err := env.Engine.Scan(context.Background(), catalog.Selection{}, Network, nil)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[model.Kind]bool{}
	for _, tr := range rep.Targets {
		kinds[tr.Verdict.Kind] = true
	}
	for _, k := range []model.Kind{model.KindOK, model.KindSNIDPI, model.KindDNS, model.KindIPBlock,
		model.KindThrottleFreeze, model.KindThrottleRate, model.KindBlockpage, model.KindTLSMITM} {
		if !kinds[k] {
			t.Errorf("demo is missing verdict %s", k)
		}
	}
	if !rep.Options.Demo {
		t.Error("demo flag not set")
	}
	if rep.DNS == nil || len(rep.DNS.Findings) == 0 {
		t.Error("demo should show DNS findings")
	}

	// Every renderer must work on the demo report and never leak IP addresses
	// of the user (the demo has none; server IPs are allowed only in JSON).
	b := i18n.New("ru")
	v := report.Build(rep, b, nil)
	for name, render := range map[string]func(*bytes.Buffer) error{
		"terminal": func(w *bytes.Buffer) error { return report.WriteTerminal(w, v, report.TerminalOptions{Verbose: true}) },
		"markdown": func(w *bytes.Buffer) error { return report.WriteMarkdown(w, v) },
		"html":     func(w *bytes.Buffer) error { return report.WriteHTML(w, v) },
	} {
		var buf bytes.Buffer
		if err := render(&buf); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := buf.String()
		if !strings.Contains(out, "Messenger A") || !strings.Contains(out, b.T("app.demo_banner")) {
			t.Errorf("%s output incomplete", name)
		}
	}
	var html bytes.Buffer
	_ = report.WriteHTML(&html, v)
	if regexp.MustCompile(`(?i)<script|https?://[^"' ]+\.(js|css)`).Match(html.Bytes()) {
		t.Error("HTML report must be self-contained and script-free")
	}

	wl, err := env.Engine.Whitelist(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if wl.Verdict != model.WhitelistActive {
		t.Errorf("demo whitelist verdict %s", wl.Verdict)
	}
}
