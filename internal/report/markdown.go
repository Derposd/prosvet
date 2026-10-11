package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/ordinarysim/prosvet/internal/model"
)

var statusEmoji = map[model.Status]string{
	model.StatusOK:          "🟢",
	model.StatusThrottled:   "🟡",
	model.StatusPartial:     "🟠",
	model.StatusBlocked:     "🔴",
	model.StatusUnreachable: "⚫",
	model.StatusUnknown:     "⚪",
}

// WriteMarkdown renders the report as GitHub-flavoured Markdown.
func WriteMarkdown(w io.Writer, v *View) error {
	var sb strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&sb, format, a...) }
	esc := func(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

	p("# %s\n\n", v.Labels.Title)
	if v.Demo {
		p("> ⚠️ **%s**\n\n", v.DemoBanner)
	}
	p("**%s:** %s  \n", v.Labels.Network, v.Network.Line)
	if v.Started != "" {
		p("**%s:** %s (%s)\n\n", v.Labels.Date, v.Started, v.Duration)
	}
	for _, n := range v.Notices {
		p("> ⚠️ %s\n\n", n)
	}
	p("**%s:** %s\n\n", v.Labels.Summary, v.SummaryText)

	for _, g := range v.Groups {
		p("## %s\n\n", g.Title)
		p("| | %s | %s | %s | %s |\n|---|---|---|---|---|\n", v.Labels.Service, v.Labels.Status, v.Labels.Method, v.Labels.Confidence)
		for _, t := range g.Targets {
			method, conf := "—", "—"
			if t.Status != model.StatusOK {
				method = t.KindTitle
				if t.Subtype != "" {
					method += " (" + t.Subtype + ")"
				}
				conf = t.Confidence
			} else if len(t.Secondary) > 0 {
				method = strings.Join(t.Secondary, ", ")
			}
			p("| %s | %s | %s | %s | %s |\n", statusEmoji[t.Status], esc(t.Name), esc(t.StatusText), esc(method), esc(conf))
		}
		p("\n")
	}

	if len(v.Problems) > 0 {
		p("## %s\n\n", v.Labels.Problems)
		for _, t := range v.Problems {
			p("### %s %s — %s\n\n", statusEmoji[t.Status], t.Name, t.KindTitle)
			p("%s\n\n", t.Explain)
			for _, e := range t.Evidence {
				p("- %s\n", e)
			}
			if len(t.Secondary) > 0 {
				p("- %s: %s\n", v.Labels.Secondary, strings.Join(t.Secondary, ", "))
			}
			if len(t.Endpoints) > 1 {
				p("\n<details><summary>%s</summary>\n\n", v.Labels.Endpoints)
				for _, e := range t.Endpoints {
					label := e.KindTitle
					if e.Subtype != "" {
						label += " (" + e.Subtype + ")"
					}
					p("- `%s` — %s\n", e.Name, label)
				}
				p("\n</details>\n")
			}
			if t.Expect != "" {
				p("\n_%s_\n", t.Expect)
			}
			p("\n")
		}
	}

	if v.DNS != nil {
		p("## %s\n\n", v.Labels.DNS)
		if len(v.DNS.Findings) == 0 {
			p("%s\n\n", v.Labels.DNSNone)
		}
		for _, f := range v.DNS.Findings {
			p("- %s\n", f)
		}
		p("\n")
	}
	if v.Whitelist != nil {
		p("## %s\n\n**%s**\n\n%s\n\n%s\n", v.Labels.Whitelist, v.Whitelist.Title, v.Whitelist.Explain, v.Whitelist.Counts)
		if v.Whitelist.Level != "" {
			p("\n→ %s\n", v.Whitelist.Level)
		}
		p("\n")
	}
	if v.Baseline != "" {
		p("_%s_\n\n", v.Baseline)
	}
	p("---\n_%s_ · %s\n", v.Labels.Generated, v.Labels.PrivacyNote)
	_, err := io.WriteString(w, sb.String())
	return err
}
